#include "StdInc.h"
#include <memory>
#include <codecvt>
#include <regex>

#include <assert.h>

#include <CFileSystem.h>
#include <CFileSystem.common.stl.h>

#include <peframework.h>

#include <gtaconfig/include.h>

#include "mangle.h"

// Get PDB headers.
#include "msft_pdb/include/cvinfo.h"
#include "msft_pdb/langapi/include/pdb.h"
#include "msft_pdb/langapi/shared/crc32.h"

#include <Shellapi.h>

extern CFileSystem *fileSystem;

// From other compilation modules (for a reason).
void tryGenerateSamplePDB( PEFile& peFile, CFileTranslator *outputRoot, const filePath& outPathWithoutExt );

static void printHeader( void )
{
    printf(
        "PEframework PE file debug extender written by The_GTA\n" \
        "Made to advance the professionality of the GTA community hacking experience\n" \
        "wordwhirl@outlook.de\n\n"
    );
}

int main( int _, char *__[] )
{
    printHeader();

    // Parse the command line.
    const wchar_t *cmdLine = GetCommandLineW();

    int argc;

    const wchar_t *const *cmdArgs = CommandLineToArgvW( cmdLine, &argc );

    if ( cmdArgs == NULL )
    {
        printf( "failed to parse command line arguments\n" );
        return -1;
    }

    // Get the filename from the arguments, at least.
    if ( argc < 2 )
    {
        printf( "too little arguments; at least path to executable required\n" );
        return -1;
    }

    std::wstring cfgExecutablePath;
    {
        // We skip the source executable path.
        for ( int n = 1; n < argc; n++ )
        {
            if ( n != 1 )
            {
                cfgExecutablePath += L" ";
            }

            cfgExecutablePath += cmdArgs[ n ];
        }
    }

    // We want to read our own PE executable.
    // After that we want to write it out again in the exactly same format.
    fs_construction_params constrParam;
    constrParam.nativeExecMan = NULL;

    CFileSystem::Create( constrParam );

    bool successful = false;

    try
    {
        try
        {
            PEFile filedata;

            bool gotInputData = false;

            filePath executablePath( cfgExecutablePath.c_str(), cfgExecutablePath.size() );

            // Attempt to parse the path through the current application directory.
            fileRoot->GetFullPathFromRoot( cfgExecutablePath.c_str(), true, executablePath );

            // Get access to the input file root.
            std::unique_ptr <CFileTranslator> workInputRoot( fileSystem->CreateSystemMinimumAccessPoint( executablePath ) );

            if ( workInputRoot )
            {
                // Read the PE file.
                std::unique_ptr <CFile> filePtr( workInputRoot->Open( executablePath, "rb" ) );

                if ( filePtr )
                {
                    FileSystem::fileStreamBuf stlBuf( filePtr.get() );
                    std::iostream stlStream( &stlBuf );

                    PEStreamSTL peStream( &stlStream );

                    printf( "found input file, processing...\n" );

                    filedata.LoadFromDisk( &peStream );

                    printf( "loaded input file from disk\n" );

                    gotInputData = true;
                }
                else
                {
                    printf( "failed to find input file\n" );
                }
            }
            else
            {
                printf( "failed to get handle to input work folder\n" );
            }

            if ( gotInputData )
            {
                // Next up is deciding on an output file root, which can be inside by the input executable or if not possible by
                // the running executable.
                CFileTranslator *outputRoot = NULL;
                bool isOutputRootShared = false;
                // * EXE PATH.
                {
                    outputRoot = fileSystem->CreateTranslator( executablePath, DIR_FLAG_WRITABLE );

                    if ( outputRoot )
                    {
                        printf( "chose EXE original location as output\n" );
                    }
                }
                // * RUNNING PATH.
                if ( !outputRoot )
                {
                    outputRoot = fileRoot;

                    isOutputRootShared = true;

                    printf( "chose running path as output\n" );
                }

                if ( outputRoot )
                {
                    try
                    {
                        // Decide on the PE image type what output filename we should pick.
                        filePath outFileName;
                        outputRoot->GetFullPathFromRoot( "@", false, outFileName );

                        // First get the same target directory as the input file.
                        filePath nameItem = FileSystem::GetFileNameItem( cfgExecutablePath.c_str(), false, NULL, NULL );

                        assert( nameItem.empty() == false );

                        outFileName += nameItem;
                        outFileName += "_debug";

                        // Do some PDB magic I guess.
                        tryGenerateSamplePDB( filedata, outputRoot, outFileName );

                        // We get the extension from the PE file format.
                        if ( filedata.IsDynamicLinkLibrary() )
                        {
                            outFileName += ".dll";
                        }
                        else
                        {
                            outFileName += ".exe";
                        }

                        // Write it to another location.
                        // This is a test that we can 1:1 convert executables.
                        // We want to be able to write into any location.
                        std::unique_ptr <CFile> outFilePtr( outputRoot->Open( outFileName, "wb" ) );

                        if ( outFilePtr )
                        {
                            FileSystem::fileStreamBuf stlBuf( outFilePtr.get() );
                            std::iostream stlStream( &stlBuf );

                            PEStreamSTL peStream( &stlStream );

                            printf( "writing PE file\n" );

                            filedata.WriteToStream( &peStream );

                            printf( "done!\n" );

                            successful = true;
                        }
                        else
                        {
                            printf( "failed to create output PE file\n" );
                        }
                    }
                    catch( ... )
                    {
                        if ( !isOutputRootShared )
                        {
                            delete outputRoot;
                        }

                        throw;
                    }

                    if ( !isOutputRootShared )
                    {
                        delete outputRoot;
                    }
                }
            }
        }
        catch( ... )
        {
            CFileSystem::Destroy( fileSystem );

            throw;
        }

        // Clean-up.
        CFileSystem::Destroy( fileSystem );
    }
    catch( peframework_exception& except )
    {
        printf( "error while processing PE file: %s\n", except.desc_str() );

        // Just continue.
    }
    catch( std::exception& except )
    {
        printf( "STL C++ error while processing: %s\n", except.what() );

        // Just continue.
    }

    if ( successful )
    {
        printf( "\n\nHave fun!\n" );
    }

    // :-)
    return ( successful ? 0 : -2 );
}