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

static inline PEFile::PESection* embed_file_as_section( PEFile& inputImage, CFile *tempFile )
{
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
        tempFile->Read( dstDataPtr, (size_t)realWriteSize );
    }
    embedSect.Finalize();

    return inputImage.AddSection( std::move( embedSect ) );
}

static inline void write_section_reference( PEFile& inputImage, PEFile::PESectionDataReference& refToWriteAt, PEFile::PESection *sectionToLink )
{
    // Write a negotiated structure at the export location.
    // 1) void *dataloc
    // 2) size_t dataSize
    // Members must be in the input image platform format (32bit or 64bit, ie).
    // We must write base relocation information if required.
    // Members have to be initialized to 0 statically, can be placed in const memory.
    PEFile::PESection *expSect = refToWriteAt.GetSection();
    std::uint32_t expSectOff = refToWriteAt.GetSectionOffset();

    expSect->stream.Seek( (int32_t)expSectOff );

    if ( inputImage.isExtendedFormat )
    {
        std::uint64_t vaCompressedData = ( inputImage.GetImageBase() + sectionToLink->ResolveRVA( 0 ) );

        // DATALOC.
        expSect->stream.WriteUInt64( vaCompressedData );
        // DATASIZE.
        expSect->stream.WriteUInt64( (std::uint64_t)sectionToLink->stream.Size() );
    }
    else
    {
        std::uint32_t vaCompressedData = ( (std::uint32_t)inputImage.GetImageBase() + sectionToLink->ResolveRVA( 0 ) );

        // DATALOC.
        expSect->stream.WriteUInt32( vaCompressedData );
        // DATASIZE.
        expSect->stream.WriteUInt32( (std::uint32_t)sectionToLink->stream.Size() );
    }
    inputImage.OnWriteAbsoluteVA( expSect, expSectOff, inputImage.isExtendedFormat );
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
            "* USAGE: peresembed -zipfldr *FOLDER_PATH* *EXP_NAME* *INPUT_EXE_PATH* *OUTPUT_EXE_PATH*\n"
            "-file: puts a file into application memory space\n"
            "* USAGE: peresembed -file *FILE_PATH* *EXP_NAME* *INPUT_EXE_PATH* *OUTPUT_EXE_PATH*\n"
            "-resfldr: puts all files from a folder into the application resource tree\n"
            "* USAGE: peresembed -resfldr *FOLDER_PATH* *INPUT_EXE_PATH* *OUTPUT_EXE_PATH*\n"
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

                size_t file_count = 0;

                accessRoot->ScanDirectory( "/", "*", true, nullptr,
                    [&]( const filePath& absFilePath )
                {
                    filePath relFilePath;
                    accessRoot->GetRelativePathFromRoot( absFilePath, true, relFilePath );

                    FileSystem::FileCopy( accessRoot, absFilePath, zipFolder, relFilePath );
                    
                    // Statistics.
                    file_count++;

                    // Output a nice message.
                    {
                        auto ansiFilePath = absFilePath.convert_ansi <FileSysCommonAllocator> ();

                        printf( "* %s\n", ansiFilePath.GetConstString() );
                    }
                }, nullptr );

                // Output nice stats.
                printf( "added %zu files to archive\n", file_count );

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

            PEFile::PESection *newSect = embed_file_as_section( inputImage, tempFile );

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

            write_section_reference( inputImage, requestedExport.expRef, newSect );

            if ( keepExport == false )
            {
                printf( "removing export by name\n" );

                // TODO: also remove the export by ordinal but then adjust all export ordinals
                // to point to their correct/decremented entries.

                // Remove the named export.
                inputImage.exportDir.funcNameMap.RemoveNode( findExportNode );

                // Rewrite the information.
                inputImage.exportDir.funcNamesAllocEntry = PEFile::PESectionAllocation();
            }

            // Write the PE image back to disk.
            {
                FileSystem::filePtr outputPEStream = open_stream_redir( outputExecFilePath, "wb", -7, "output image" );

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

            if ( args_remaining < 1 )
            {
                printf( "missing path to file to embed\n" );
                return -3;
            }

            filePath pathFileToEmbed = argv[ argToStartFrom + 0 ];

            if ( args_remaining < 2 )
            {
                printf( "missing export name for resolution\n" );
                return -3;
            }

            peString <char> exportName = argv[ argToStartFrom + 1 ];

            if ( args_remaining < 3 )
            {
                printf( "missing path to input executable\n" );
                return -3;
            }

            filePath pathToInputExec = argv[ argToStartFrom + 2 ];

            if ( args_remaining < 4 )
            {
                printf( "missing path for output executable writing\n" );
                return -3;
            }

            filePath pathToOutputExec = argv[ argToStartFrom + 3 ];

            printf( "loading input image\n" );

            // First we load the input image.
            PEFile inputImage;
            {
                FileSystem::filePtr inputImageStream = open_stream_redir( pathToInputExec, "rb", -4, "input image" );

                PEStreamFS stream( inputImageStream );

                try
                {
                    inputImage.LoadFromDisk( &stream );
                }
                catch( peframework_exception& )
                {
                    printf( "failed to load input PE image\n" );
                    return -5;
                }
            }

            printf( "resolving requested export '%s'\n", exportName.GetConstString() );

            // Then we resolve the export.
            auto *findExportNode = inputImage.exportDir.funcNameMap.Find( exportName );

            if ( findExportNode == nullptr )
            {
                printf( "failed to resolve export in input image\n" );
                return -6;
            }

            size_t exportIndex = findExportNode->GetValue();

            PEFile::PEExportDir::func& exportEntry = inputImage.exportDir.functions[ exportIndex ];

            if ( exportEntry.isForwarder )
            {
                printf( "error: requested export is a forwarder\n" );
                return -7;
            }

            printf( "embedding file into input image\n" );

            PEFile::PESection *newSect;
            {
                // Open the file that we want to embed.
                FileSystem::filePtr fileToEmbedStream = open_stream_redir( pathFileToEmbed, "rb", -8, "embed file" );

                // Thus we write the file into a section.
                newSect = embed_file_as_section( inputImage, fileToEmbedStream );
            }

            if ( newSect == nullptr )
            {
                printf( "failed to embed given file for embedding as PE section\n" );
                return -10;
            }

            if ( keepExport == false )
            {
                printf( "removing export by name\n" );

                // TODO: also remove the export by ordinal but then adjust all export ordinals
                // to point to their correct/decremented entries.

                // Remove the named export.
                inputImage.exportDir.funcNameMap.RemoveNode( findExportNode );

                // Rewrite the information.
                inputImage.exportDir.funcNamesAllocEntry = PEFile::PESectionAllocation();
            }

            printf( "patching executable memory with the export data reference\n" );

            // Write the reference to the section into the image export.
            write_section_reference( inputImage, exportEntry.expRef, newSect );

            printf( "writing output image...\n" );

            // Finish by writing image back to disk.
            {
                FileSystem::filePtr outputFileStream = open_stream_redir( pathToOutputExec, "wb", -11, "output image" );

                PEStreamFS stream( outputFileStream );

                try
                {
                    inputImage.WriteToStream( &stream );
                }
                catch( peframework_exception& )
                {
                    printf( "failed to write output PE image\n" );
                    return -13;
                }
            }

            printf( "done.\n" );
        }
        else if ( mode == eProcessingMode::RESOURCE_EMBED )
        {
            printf( "embedding folder as resources\n" );

            if ( args_remaining < 1 )
            {
                printf( "missing path to input folder for embedding\n" );
                return -3;
            }

            filePath pathToEmbedFolder = argv[ argToStartFrom + 0 ];

            if ( args_remaining < 2 )
            {
                printf( "missing path to input executable\n" );
                return -3;
            }

            filePath pathToInputExec = argv[ argToStartFrom + 1 ];

            if ( args_remaining < 3 )
            {
                printf( "missing path for output executable writing\n" );
                return -3;
            }

            filePath pathToOutputExec = argv[ argToStartFrom + 2 ];

            printf( "loading input image\n" );

            // First we load the input image.
            PEFile inputImage;
            {
                FileSystem::filePtr inputImageStream = open_stream_redir( pathToInputExec, "rb", -4, "input image" );

                PEStreamFS stream( inputImageStream );

                try
                {
                    inputImage.LoadFromDisk( &stream );
                }
                catch( peframework_exception& )
                {
                    printf( "failed to load input PE image\n" );
                    return -5;
                }
            }

            // Prepare a section for data embedding.
            PEFile::PESection embedSect;
            embedSect.shortName = ".rembed";
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

            printf( "embedding resources...\n" );

            // Next we loop through all files in the embed folder and put them as resources into the image.
            {
                FileSystem::fileTrans embedRoot = open_root_dir( fileRoot, pathToEmbedFolder, -6, "embed root" );

                size_t embedCount = 0;

                embedRoot->ScanDirectory( "/", "*", true, nullptr,
                    [&]( const filePath& absFilePath )
                {
                    // Print a nice message.
                    {
                        auto ansiAbsPath = absFilePath.convert_ansi <FileSysCommonAllocator> ();

                        printf( "* %s ...", ansiAbsPath.GetConstString() );
                    }

                    // Turn it into a relative node path from the embed root.
                    bool isFile;
                    dirNames relFileNodePath;

                    embedRoot->GetRelativePathNodesFromRoot( absFilePath, relFileNodePath, isFile );

                    assert( isFile == true );

                    FileSystem::filePtr stream = embedRoot->Open( absFilePath, "rb" );

                    if ( stream.is_good() == false )
                    {
                        printf( "failed to open file for embedding.\n" );
                        return;
                    }

                    // First we embed the file into the section.
                    std::uint32_t file_off = (std::uint32_t)embedSect.stream.Tell();

                    fsOffsetNumber_t _file_size = stream->GetSizeNative();

                    std::uint32_t real_file_size = (std::uint32_t)_file_size;

                    // Expand the section memory space.
                    int32_t target_seek = embedSect.stream.Tell() + (int32_t)real_file_size;
                    embedSect.stream.Truncate( target_seek );
                    {
                        void *dstDataPtr = (char*)embedSect.stream.Data() + file_off;
                        stream->Read( dstDataPtr, (size_t)real_file_size );
                    }
                    embedSect.stream.Seek( target_seek );

                    // Create our data reference.
                    PEFile::PESectionDataReference dataRef( &embedSect, file_off, real_file_size );

                    // Get to the resource directory.
                    PEFile::PEResourceDir *putDir = &inputImage.resourceRoot;

                    size_t numDirItems = ( relFileNodePath.GetCount() - 1 );

                    for ( size_t n = 0; n < numDirItems; n++ )
                    {
                        filePath nodeName = relFileNodePath[ n ];

                        nodeName.transform_to <char16_t> ();

                        peString <char16_t> wideNodeName( nodeName.to_char <char16_t> (), nodeName.size() );

                        putDir = putDir->MakeDir( false, std::move( wideNodeName ), 0 );

                        assert( putDir != nullptr );
                    }

                    // Then create our data node.
                    filePath dataNodeName = std::move( relFileNodePath[ numDirItems ] );

                    dataNodeName.transform_to <char16_t> ();

                    peString <char16_t> wideNodeName( dataNodeName.to_char <char16_t> (), dataNodeName.size() );

                    PEFile::PEResourceInfo *dataNode = putDir->PutData( false, std::move( wideNodeName ), 0, std::move( dataRef ) );

                    if ( dataNode )
                    {
                        printf( "ok.\n" );

                        // Statistics.
                        embedCount++;
                    }
                    else
                    {
                        printf( "failed to add.\n" );
                    }

                }, nullptr );

                printf( "total embed count: %zu\n", embedCount );
            }

            // Then we finalize + insert our embedding section.
            embedSect.Finalize();

            printf( "adding PE section to image\n" );

            PEFile::PESection *newSect = inputImage.AddSection( std::move( embedSect ) );

            if ( newSect == nullptr )
            {
                printf( "failed to add PE section with resources to executable image\n" );
                return -6;
            }

            printf( "writing output image...\n" );

            // Write our new image.
            {
                FileSystem::filePtr outputImageStream = open_stream_redir( pathToOutputExec, "wb", -7, "output image" );

                PEStreamFS stream( outputImageStream );

                try
                {
                    inputImage.WriteToStream( &stream );
                }
                catch( peframework_exception& )
                {
                    printf( "failed to write output PE image\n" );
                    return -8;
                }
            }

            printf( "done.\n" );
        }
        else
        {
            printf( "mode not implemented.\n" );

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