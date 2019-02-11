#include <peframework.h>
#include <CFileSystem.h>
#include <gtaconfig/include.h>

int main( int argc, const char *argv[] )
{
    if ( argc < 1 )
    {
        return -1;
    }

    // We do not care about the application path.
    argc--;

    // Parse the command line.
    OptionParser parser( &argv[1], (size_t)argc );

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
        );

        if ( mode == eProcessingMode::UNKNOWN )
        {
            printf( "no processing mode selected; aborting.\n" );
        }

        return 0;
    }

    size_t argToStartFrom = parser.GetArgIndex();

    if ( mode == eProcessingMode::FOLDER_ZIP_EMBED )
    {

    }
    else if ( mode == eProcessingMode::FILE_EMBED )
    {

    }
    else if ( mode == eProcessingMode::RESOURCE_EMBED )
    {

    }
    else
    {
        return -2;
    }

    return 0;
}