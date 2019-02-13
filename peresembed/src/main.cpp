#include <peframework.h>
#include <CFileSystem.h>
#include <gtaconfig/include.h>

#include "utils.hxx"

struct basic_runtime_exception
{
    inline basic_runtime_exception( int code, peString <char> desc ) : retcode( code ), msg( std::move( desc ) )
    {
        return;
    }

    inline int get_code( void ) const
    {
        return retcode;
    }

    inline const char* get_msg( void ) const
    {
        return msg.GetConstString();
    }

private:
    int retcode;
    peString <char> msg;
};

static FileSystem::filePtr open_stream_redir( const filePath& location, const filePath& mode, int fail_ret_code, const char *descName )
{
    FileSystem::filePtr inputPEStream( fileRoot, location, mode );

    if ( !inputPEStream.is_good() )
    {
        filePath rootDesc;

        if ( fileSystem->GetSystemRootDescriptor( location, rootDesc ) )
        {
            // Try to fetch a system root access point.
            FileSystem::fileTrans inputPERoot = fileSystem->CreateSystemMinimumAccessPoint( rootDesc );

            if ( inputPERoot.is_good() )
            {
                inputPEStream = FileSystem::filePtr( inputPERoot, location, "rb" );
            }
        }
    }

    if ( !inputPEStream.is_good() )
    {
        peString <char> error_msg = "coult not open ";
        error_msg += descName;

        throw basic_runtime_exception( fail_ret_code, std::move( error_msg ) );
    }

    return inputPEStream;
}

static FileSystem::fileTrans open_root_dir( CFileTranslator *base, const filePath& location, int fail_ret_code, const char *descName )
{
    // First try to create directly from the base.
    {
        filePath fromBase;

        if ( base->GetFullPathFromRoot( location, false, fromBase ) )
        {
            if ( CFileTranslator *trans = fileSystem->CreateTranslator( fromBase ) )
            {
                return trans;
            }
        }
    }

    // Next try to create from system drive.
    {
        filePath rootDesc;

        if ( fileSystem->GetSystemRootDescriptor( location, rootDesc ) )
        {
            if ( CFileTranslator *trans = fileSystem->CreateTranslator( rootDesc ) )
            {
                return trans;
            }
        }
    }

    // Error out.
    peString <char> err_msg( "failed to bind " );
    err_msg += descName;
    err_msg += " directory";

    throw basic_runtime_exception( fail_ret_code, std::move( err_msg ) );
}

int main( int argc, const char *argv[] )
{
    if ( argc < 1 )
    {
        return -1;
    }

    size_t s_argc = (size_t)argc;

    // Parse the command line.
    OptionParser parser( &argv[1], s_argc - 1 );

    enum class eProcessingMode
    {
        UNKNOWN,
        FOLDER_ZIP_EMBED,
        FILE_EMBED,
        RESOURCE_EMBED
    };

    // Check out what the user wants.
    bool wantsHelp = false;
    eProcessingMode mode = eProcessingMode::UNKNOWN;
    bool keepExport = false;

    while ( true )
    {
        std::string curOpt = parser.FetchOption();
        
        if ( curOpt.empty() )
        {
            break;
        }

        if ( curOpt == "h" || curOpt == "help" || curOpt == "?" )
        {
            wantsHelp = true;
        }
        else if ( curOpt == "zipfldr" )
        {
            mode = eProcessingMode::FOLDER_ZIP_EMBED;
        }
        else if ( curOpt == "file" )
        {
            mode = eProcessingMode::FILE_EMBED;
        }
        else if ( curOpt == "resfldr" )
        {
            mode = eProcessingMode::RESOURCE_EMBED;
        }
        else if ( curOpt == "keepexp" )
        {
            keepExport = true;
        }
    }

    printf(
        "peresembed - PE File Resource Embedding Tool by (c)Martin Turski\n"
        "Allows you to put resources into executables post-compilation\n\n"
    );

    if ( wantsHelp || mode == eProcessingMode::UNKNOWN )
    {
        printf(
            "-h/-help/-?: displays this help text\n"
            "-zipfldr: compresses a target folder as .ZIP and puts it into application memory space\n"
            "-file: puts a file into application memory space\n"
            "-resfldr: puts all files from a folder into the application resource tree\n"
            "-keepexp: if operation resolves an export then keep the export after resolution\n"
        );

        if ( mode == eProcessingMode::UNKNOWN )
        {
            printf( "no processing mode selected; aborting.\n" );
        }

        return 0;
    }

    FileSystem::fileSysInstance fileSys;

    size_t argToStartFrom = ( parser.GetArgIndex() + 1 );
    size_t args_remaining = ( s_argc - argToStartFrom );

    try
    {
        if ( mode == eProcessingMode::FOLDER_ZIP_EMBED )
        {
            printf( "embedding folder as ZIP file\n" );

            if ( args_remaining < 1 )
            {
                printf( "missing input folder path\n" );
                return -3;
            }

            filePath inputFolderPath = argv[ argToStartFrom + 0 ];

            if ( args_remaining < 2 )
            {
                printf( "missing PE export name\n" );
                return -3;
            }

            peString <char> exportName = argv[ argToStartFrom + 1 ];

            if ( args_remaining < 3 )
            {
                printf( "missing input executable file path\n" );
                return -3;
            }

            filePath inputExecFilePath = argv[ argToStartFrom + 2 ];

            if ( args_remaining < 4 )
            {
                printf( "missing output executable file path\n" );
                return -3;
            }

            filePath outputExecFilePath = argv[ argToStartFrom + 3 ];

            // Create a target archive.
            FileSystem::filePtr tempFile = fileSys->CreateMemoryFile();
            {
                FileSystem::archiveTrans zipFolder = fileSys->CreateZIPArchive( *tempFile );

                // Put all files from the folder into our zip archive.
                FileSystem::fileTrans accessRoot = open_root_dir( fileRoot, inputFolderPath, -4, "input folder" );

                printf( "compressing archive...\n" );

                accessRoot->ScanDirectory( "/", "*", true, nullptr,
                    [&]( const filePath& absFilePath )
                {
                    filePath relFilePath;
                    accessRoot->GetRelativePathFromRoot( absFilePath, true, relFilePath );

                    FileSystem::FileCopy( accessRoot, absFilePath, zipFolder, relFilePath );

                    // Output a nice message.
                    {
                        auto ansiFilePath = absFilePath.convert_ansi();

                        printf( "* %s\n", ansiFilePath.GetConstString() );
                    }
                }, nullptr );

                printf( "writing .ZIP ..." );

                // Save the .ZIP archive.
                zipFolder->Save();

                printf( "done.\n" );
            }

            // We now have the .ZIP archive in our temporary file.
            // Write it into the input executable, as PE section.
            PEFile inputImage;
            {
                FileSystem::filePtr inputPEStream = open_stream_redir( inputExecFilePath, "rb", -6, "input exec file" );

                PEStreamFS stream( inputPEStream );

                try
                {
                    inputImage.LoadFromDisk( &stream );
                }
                catch( peframework_exception& )
                {
                    printf( "failed to read PE image\n" );
                    return -7;
                }
            }

            printf( "embedding archive into image\n" );

            // We can only write as much as a section allows.
            std::int32_t realWriteSize = (std::int32_t)tempFile->GetSizeNative();

            // For writing we seek our archive file back to start.
            tempFile->SeekNative( 0, SEEK_SET );

            // For that we create a new section.
            PEFile::PESection embedSect;
            embedSect.shortName = ".embed";
            embedSect.chars.sect_containsCode = false;
            embedSect.chars.sect_containsInitData = false;
            embedSect.chars.sect_containsUninitData = false;
            embedSect.chars.sect_mem_farData = false;
            embedSect.chars.sect_mem_purgeable = true;
            embedSect.chars.sect_mem_locked = false;
            embedSect.chars.sect_mem_preload = true;
            embedSect.chars.sect_mem_discardable = true;
            embedSect.chars.sect_mem_not_cached = true;
            embedSect.chars.sect_mem_not_paged = false;
            embedSect.chars.sect_mem_shared = false;
            embedSect.chars.sect_mem_execute = false;
            embedSect.chars.sect_mem_read = true;
            embedSect.chars.sect_mem_write = false;
            embedSect.stream.Truncate( realWriteSize );
            {
                void *dstDataPtr = embedSect.stream.Data();
                tempFile->Read( dstDataPtr, 1, (size_t)realWriteSize );
            }
            embedSect.Finalize();

            PEFile::PESection *newSect = inputImage.AddSection( std::move( embedSect ) );

            if ( newSect == nullptr )
            {
                printf( "failed to add section to PE image\n" );
                return -8;
            }

            printf( "resolving named export '%s'\n", exportName.GetConstString() );

            // Resolve the requested export.
            auto *findExportNode = inputImage.exportDir.funcNameMap.Find( exportName );

            if ( findExportNode == nullptr )
            {
                printf( "could not find the requested export inside the PE image\n" );
                return -9;
            }

            size_t requestedExportIndex = findExportNode->GetValue();

            PEFile::PEExportDir::func& requestedExport = inputImage.exportDir.functions[ requestedExportIndex ];

            if ( requestedExport.isForwarder )
            {
                printf( "error: requested export is forwarder\n" );
                return -10;
            }

            printf( "patching executable memory with the export data reference\n" );

            // Write a negotiated structure at the export location.
            // 1) void *dataloc
            // 2) size_t dataSize
            // Members must be in the input image platform format (32bit or 64bit, ie).
            // We must write base relocation information if required.
            // Members have to be initialized to 0 statically, can be placed in const memory.
            PEFile::PESection *expSect = requestedExport.expRef.GetSection();
            std::uint32_t expSectOff = requestedExport.expRef.GetSectionOffset();

            expSect->stream.Seek( (int32_t)expSectOff );

            if ( inputImage.isExtendedFormat )
            {
                std::uint64_t vaCompressedData = ( inputImage.GetImageBase() + newSect->ResolveRVA( 0 ) );

                // DATALOC.
                expSect->stream.WriteUInt64( vaCompressedData );
                // DATASIZE.
                expSect->stream.WriteUInt64( (std::uint64_t)realWriteSize );
            }
            else
            {
                std::uint32_t vaCompressedData = ( (std::uint32_t)inputImage.GetImageBase() + newSect->ResolveRVA( 0 ) );

                // DATALOC.
                expSect->stream.WriteUInt32( vaCompressedData );
                // DATASIZE.
                expSect->stream.WriteUInt32( (std::uint32_t)realWriteSize );
            }
            inputImage.OnWriteAbsoluteVA( expSect, expSectOff, inputImage.isExtendedFormat );

            if ( keepExport == false )
            {
                printf( "removing export by ordinal and name\n" );

                // Remove the named export.
                inputImage.exportDir.funcNameMap.RemoveNode( findExportNode );
                inputImage.exportDir.functions.RemoveByIndex( requestedExportIndex );

                // Rewrite the information.
                inputImage.exportDir.funcNamesAllocEntry = PEFile::PESectionAllocation();
                inputImage.exportDir.funcAddressAllocEntry = PEFile::PESectionAllocation();
            }

            // Write the PE image back to disk.
            {
                FileSystem::fileTrans outputRootDir = open_root_dir( fileRoot, outputExecFilePath, -7, "output root" );

                FileSystem::filePtr outputPEStream( outputRootDir, outputExecFilePath, "wb" );

                PEStreamFS stream( outputPEStream );

                printf( "writing output image...\n" );

                try
                {
                    inputImage.WriteToStream( &stream );
                }
                catch( peframework_exception& )
                {
                    printf( "failed to write PE image\n" );
                    return -8;
                }
            }

            printf( "done.\n" );
        }
        else if ( mode == eProcessingMode::FILE_EMBED )
        {
            printf( "embedding simple file\n" );


        }
        else if ( mode == eProcessingMode::RESOURCE_EMBED )
        {
            printf( "embedding folder as resources\n" );


        }
        else
        {
            return -2;
        }
    }
    catch( basic_runtime_exception& except )
    {
        printf( "%s\n", except.get_msg() );

        return except.get_code();
    }

    return 0;
}