#include "StdInc.h"
#include <memory>
#include <codecvt>
#include <regex>

#include <assert.h>

#include <CFileSystem.h>

#include <peframework.h>

#include <gtaconfig/include.h>

#include "mangle.h"

// Get PDB headers.
#include "msft_pdb/include/cvinfo.h"
#include "msft_pdb/langapi/include/pdb.h"
#include "msft_pdb/langapi/shared/crc32.h"

#undef VOID
#undef CDECL

// Utility to parse debug information from a text file, created by an IDC script...
// https://www.hex-rays.com/products/ida/support/freefiles/dumpinfo.idc
struct nameInfo
{
    std::string name;
    std::uint64_t absolute_va;
};
typedef std::vector <nameInfo> symbolNames_t;

static const std::regex patternMatchItem( "[\\w\\d\\.]+\\:([0123456789aAbBcCdDeEfF]+)[\\s\\t]+\\(([^)]+)\\)[\\s\\t]+(.+)" );

static symbolNames_t ParseSymbolNames( CFile *inputStream )
{
    symbolNames_t symbols;

    // We skip 11 lines.
    for ( size_t n = 0; n < 11; n++ )
    {
        std::string _skipContent;

        Config::GetConfigLine( inputStream, _skipContent );
    }

    // Read all entries.
    while ( inputStream->IsEOF() == false )
    {
        std::string lineCont;

        bool gotLine = Config::GetConfigLine( inputStream, lineCont );

        if ( gotLine )
        {
            std::smatch results;

            bool gotMatch = std::regex_match( lineCont, results, patternMatchItem );

            if ( gotMatch && results.size() == 4 )
            {
                std::string offset = std::move( results[ 1 ] );
                std::string typeName = std::move( results[ 2 ] );
                std::string valueString = std::move( results[ 3 ] );

                if ( typeName == "UserName" )
                {
                    try
                    {
                        nameInfo newInfo;
                        newInfo.name = std::move( valueString );
                        newInfo.absolute_va = std::stoull( offset, NULL, 16 );

                        symbols.push_back( std::move( newInfo ) );
                    }
                    catch( ... )
                    {
                        // Ignore cast error.
                    }
                }
            }
        }
    }

    return symbols;
}

// Thanks to https://www.snip2code.com/Snippet/735099/Dump-PDB-information-from-a-PE-file/
const DWORD CV_SIGNATURE_RSDS = 0x53445352; // 'SDSR'

struct CV_INFO_PDB70
{
    DWORD      CvSignature;
    SIG70      Signature;
    DWORD      Age;
    //BYTE       PdbFileName[1];
};

void tryGenerateSamplePDB( PEFile& peFile, CFileTranslator *outputRoot, const filePath& outPathWithoutExt )
{
    // Prepare symbol names from an input file.
    symbolNames_t symbols;
    {
        // We try both the output root and the file root for the symbols file.
        CFile *symbolsFile = NULL;
        // * OUTPUT ROOT.
        {
            symbolsFile = outputRoot->Open( L"symbols.txt", L"rb" );

            if ( symbolsFile )
            {
                printf( "found symbols file in output root, reading.\n" );
            }
        }
        // * FILE ROOT.
        if ( !symbolsFile && ( outputRoot != fileRoot ) )
        {
            symbolsFile = fileRoot->Open( L"symbols.txt", L"rb" );

            if ( symbolsFile )
            {
                printf( "found symbols file in working root, reading.\n" );
            }
        }

        if ( symbolsFile )
        {
            try
            {
                symbols = ParseSymbolNames( symbolsFile );

                printf( "finished reading symbols file.\n" );
            }
            catch( ... )
            {
                delete symbolsFile;

                throw;
            }

            delete symbolsFile;
        }
    }
    
    // Establish a file location.
    std::wstring widePDBFileLocation = ( outPathWithoutExt.convert_unicode() + L".pdb" );

    printf( "generating PDB file\n" );

    EC error_code_out;
    wchar_t errorBuf[ 4096 ];

    PDB *pdbHandle;

    BOOL openSuccess =
        PDB::Open2W(
            widePDBFileLocation.c_str(), "wb", &error_code_out, errorBuf, _countof(errorBuf),
            &pdbHandle
        );

    if ( openSuccess == FALSE )
    {
        // We fail in life.
        printf( "failed to create PDB file\n" );
        return;
    }

    // Yes!
    DBI *dbiHandle;

    BOOL dbiOpenSuccess =  pdbHandle->OpenDBI( NULL, "wb", &dbiHandle );

    if ( dbiOpenSuccess == TRUE )
    {
        // One step closer.

        // I guess we should try creating a module and putting symbols into it?
        // Or something else... Let's see...
        dbiHandle->SetMachineType( IMAGE_FILE_MACHINE_I386 );

        // It is a good idea to create a dummy module, at least.
        {
            Mod *mainMod = NULL;
        
            BOOL gotMainMod = dbiHandle->OpenMod( "main", "main-module (made possible by The_GTA, wordwhirl@outlook.de)", &mainMod );

            if ( gotMainMod == TRUE )
            {
                // TODO: maybe do some stuff with this.

                // Close the main mod again.
                mainMod->Close();
            }
        }

        // Embed parsed symbols as publics.
        if ( symbols.empty() == false )
        {
            printf( "embedding symbols into PDB\n" );

            CV_PUBSYMFLAGS pubflags_func;
            pubflags_func.grfFlags = 0;
            pubflags_func.fFunction = true;

            CV_PUBSYMFLAGS pubflags_data;
            pubflags_data.grfFlags = 0;

            std::uint64_t imageBase = peFile.GetImageBase();

            for ( nameInfo& infoItem : symbols )
            {
                // Convert the VA into a RVA.
                std::uint32_t rva = (std::uint32_t)( infoItem.absolute_va - imageBase );

                // Find the section associated with this item.
                // If we found it, add it as public symbol.
                std::uint32_t sectIndex = 0;

                PEFile::PESection *symbSect = peFile.FindSectionByRVA( rva, &sectIndex );

                if ( symbSect )
                {
                    // Get the offset into the section.
                    std::uint32_t native_off = ( rva - symbSect->GetVirtualAddress() );
                    
                    // If this item is in the executable section, we put a function symbol.
                    // Otherwise we put a data symbol.
                    CV_pubsymflag_t useFlags;

                    if ( symbSect->chars.sect_mem_execute )
                    {
                        useFlags = pubflags_func.grfFlags;
                    }
                    else
                    {
                        useFlags = pubflags_data.grfFlags;
                    }

                    // Try to transform the symbol name into a C++ representation if we can.
                    std::string symbName = std::move( infoItem.name );
                    {
                        ProgFunctionSymbol symbCodec;
                        bool gotSymbol = symbCodec.ParseMangled( symbName.c_str() );

                        if ( gotSymbol )
                        {
#ifdef PEDEBUG_ENABLE_FAKE_SYMBOL_INFORMATION
                            // Because IDA does not support the entirety of the Visual C++ mangle, we
                            // need to patch some things up for it so it will still support the mangled names.
                            if ( symbCodec.returnType == eSymbolValueType::UNKNOWN )
                            {
                                symbCodec.returnType = eSymbolValueType::VOID;
                            }

                            if ( symbCodec.callingConv == eSymbolCallConv::UNKNOWN )
                            {
                                symbCodec.callingConv = eSymbolCallConv::CDECL;
                            }
#endif //PEDEBUG_ENABLE_FAKE_SYMBOL_INFORMATION

                            // Remangle the name in Visual C++ format, if possible.
                            symbCodec.OutputMangled(
                                ProgFunctionSymbol::eManglingType::VISC,
                                symbName
                            );
                        }
                    }

                    // Remove previous definition of this public.
                    dbiHandle->RemovePublic( symbName.c_str() );

                    dbiHandle->AddPublic2( symbName.c_str(), sectIndex + 1, native_off, useFlags );
                }
                else
                {
                    printf( "failed to map symbol '%s' (invalid RVA)\n", infoItem.name.c_str() );
                }
            }
        }

        // Write information about all sections.
        Dbg *dbgSectHeader;

        BOOL gotSectStream = dbiHandle->OpenDbg( dbgtypeSectionHdr, &dbgSectHeader );

        if ( gotSectStream == TRUE )
        {
            // We do not want any previous data.
            dbgSectHeader->Clear();

            // Write new things.
            peFile.ForAllSections(
                [&]( PEFile::PESection *sect )
            {
                IMAGE_SECTION_HEADER header;
                strncpy( (char*)header.Name, sect->shortName.c_str(), _countof(header.Name) );
                header.Misc.VirtualSize = sect->GetVirtualSize();
                header.VirtualAddress = sect->GetVirtualAddress();
                header.SizeOfRawData = (DWORD)sect->stream.Size();
                header.PointerToRawData = 0;
                header.PointerToRelocations = 0;
                header.PointerToLinenumbers = 0;
                header.NumberOfRelocations = 0;
                header.NumberOfLinenumbers = 0;
                header.Characteristics = sect->GetPENativeFlags();

                dbgSectHeader->Append( 1, &header );
            });

            dbgSectHeader->Close();
        }

        // Remember to close our stuff.
        dbiHandle->Close();
    }

    // Make sure everything is written?
    pdbHandle->Commit();

    printf( "finished writing to PDB file!\n" );

    // Inject PDB information into the EXE file.
    {
        peFile.ClearDebugDataOfType( IMAGE_DEBUG_TYPE_CODEVIEW );

        PEFile::PEDebugDesc& cvDebug = peFile.AddDebugData( IMAGE_DEBUG_TYPE_CODEVIEW );

        PEFile::fileSpaceStream_t stream = cvDebug.dataStore.OpenStream();

        // First write the header.
        CV_INFO_PDB70 pdbDebugEntry;
        pdbDebugEntry.CvSignature = CV_SIGNATURE_RSDS;
        BOOL gotSig = pdbHandle->QuerySignature2( &pdbDebugEntry.Signature );
        pdbDebugEntry.Age = pdbHandle->QueryAge();

        assert( gotSig == TRUE );

        stream.Write( &pdbDebugEntry, sizeof(pdbDebugEntry) );

        // Inside of the EXE file we must use backslashes.
        std::replace( widePDBFileLocation.begin(), widePDBFileLocation.end(), L'/', L'\\' );

        // Create a UTF-8 version of the wide PDB location string.
        std::string utf8_pdbLoc;
        {
            std::wstring_convert <std::codecvt_utf8 <wchar_t>> utf8_conv;
            utf8_pdbLoc = utf8_conv.to_bytes( widePDBFileLocation );
        }

        // Then write the zero-terminated PDB file location, UTF-8.
        stream.Write( utf8_pdbLoc.c_str(), utf8_pdbLoc.size() + 1 );

        // Done!
    }

    printf( "injected debug information into PE file\n" );

    // Remember to close our PDB again for sanity!
    pdbHandle->Close();
}