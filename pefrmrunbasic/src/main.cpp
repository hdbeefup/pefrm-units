#include <peframework.h>

#include <fstream>

#include <Windows.h>
#undef ABSOLUTE

#include <winternl.h>

int main( int argc, char *argv[] )
{
    // Load calc.exe and run it.
    // We leave exception handling to a minimum, exercise to the reader!

    PEFile calcExec;
    {
        std::fstream exeStream( "calc.exe", std::ios::binary | std::ios::in );

        if ( !exeStream.good() )
        {
            std::cout << "failed to load executable\n";

            return -1;
        }

        PEStreamSTL stlStream( &exeStream );

        // TODO: handle exeptions here.

        calcExec.LoadFromDisk( &stlStream );
    }

    // Verify that the binary matches our platform.
    bool doesMatchMachine = false;

#ifdef _M_IX86
    if ( calcExec.pe_finfo.machine_id == IMAGE_FILE_MACHINE_I386 )
#elif defined(_M_AMD64)
    if ( calcExec.pe_finfo.machine_id == IMAGE_FILE_MACHINE_AMD64 )
#else
    if ( false )
#endif
    {
        doesMatchMachine = true;
    }

    if ( !doesMatchMachine )
    {
        std::cout << "cannot run EXE because it is compiled for a different processor\n";

        return -2;
    }

    // We need to run a normal EXE file, not a DLL.
    if ( calcExec.IsDynamicLinkLibrary() )
    {
        std::cout << "cannot run a DLL file.\n";

        return -3;
    }

    // Check that the executable is relocatable, because we cannot run otherwise.
    if ( calcExec.peOptHeader.dll_hasDynamicBase == false ||
         calcExec.HasRelocationInfo() == false )
    {
        std::cout << "EXE file not relocatable, aborting.\n";

        return -4;
    }

    // Fetch the required image size for the executable.
    std::uint64_t pe_imageBase = calcExec.GetImageBase();
    std::uint32_t imageSize = calcExec.peOptHeader.sizeOfImage;

    // We first have to allocate our executable into a special position.
    void *imageMemory = VirtualAlloc( NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );  // TODO: set proper access rights.

    assert( imageMemory != NULL );

    size_t newImageBase = (size_t)imageMemory;

    // Map the binary into address space.
    // This is done in a very basic way and it is left up to the reader to improve it.
    {
        calcExec.ForAllSections(
            [&]( PEFile::PESection *theSect )
        {
            std::uint32_t virtualAddr = theSect->GetVirtualAddress();

            std::uint32_t dataSize = (std::uint32_t)theSect->stream.Size();

            void *sectMem = ( (char*)imageMemory + virtualAddr );

            theSect->stream.Seek( 0 );
            theSect->stream.Read( sectMem, dataSize );
        });
    }

    // Relocate the binary into its space.
    {
        for ( const std::pair <const std::uint32_t, PEFile::PEBaseReloc>& relocPair : calcExec.baseRelocs )
        {
            const std::uint32_t rvaOfBlock = relocPair.first;
            
            for ( const PEFile::PEBaseReloc::item& relocItem : relocPair.second.items )
            {
                void *relocMem = ( (char*)imageMemory + rvaOfBlock * PEFile::baserelocChunkSize + relocItem.offset );

                // Depending on type, if we know it.
                PEFile::PEBaseReloc::eRelocType enumRelocType = (PEFile::PEBaseReloc::eRelocType)relocItem.type;

                if ( enumRelocType == PEFile::PEBaseReloc::eRelocType::DIR64 )
                {
                    std::uint64_t *memData = (std::uint64_t*)relocMem;

                    *memData = ( *memData - pe_imageBase ) + newImageBase;
                }
                else if ( enumRelocType == PEFile::PEBaseReloc::eRelocType::HIGHLOW )
                {
                    std::uint32_t *memData = (std::uint32_t*)relocMem;

                    *memData = (std::uint32_t)( ( *memData - pe_imageBase ) + newImageBase );
                }
                else if ( enumRelocType == PEFile::PEBaseReloc::eRelocType::ABSOLUTE )
                {
                    // We are required to ignore these.
                }
                else
                {
                    std::cout << "unknown relocation type found\n";

                    return -6;
                }
            }
        }
    }

    // Register all exception handlers.
#ifdef _M_AMD64
    {
        for ( const PEFile::PERuntimeFunction& rtFunc : calcExec.exceptRFs )
        {
            RUNTIME_FUNCTION nativeRTFunc;
            nativeRTFunc.BeginAddress = rtFunc.beginAddrRef.GetRVA();
            nativeRTFunc.EndAddress = rtFunc.endAddrRef.GetRVA();
            nativeRTFunc.UnwindInfoAddress = rtFunc.unwindInfoRef.GetRVA();
            
            BOOLEAN success = RtlAddFunctionTable( &nativeRTFunc, 1, newImageBase );

            assert( success == 1 );
        }
    }
#endif

    // Helpers for thunking.
    struct Helpers
    {
        static void InstallImportThunks( HMODULE memoryModule, IMAGE_THUNK_DATA *modThunkIter, const PEFile::PEImportDesc::functions_t& funcs )
        {
            auto thunkInfoIter = funcs.begin();

            while ( thunkInfoIter != funcs.end() )
            {
                const PEFile::PEImportDesc::importFunc& funcInfo = *thunkInfoIter;

                // Patch the function ptr.
                void *funcAddr = NULL;

                if ( funcInfo.isOrdinalImport )
                {
                    funcAddr = GetProcAddress( memoryModule, (LPCSTR)(WORD)funcInfo.ordinal_hint );
                }
                else
                {
                    funcAddr = GetProcAddress( memoryModule, funcInfo.name.c_str() );
                }

                if ( funcAddr == NULL )
                {
                    std::cout << "failed to resolve module import\n";

                    exit( -8 );
                }

                modThunkIter->u1.Function = (size_t)funcAddr;

                // Proceed to next item.
                modThunkIter++;
                thunkInfoIter++;
            }
        }
    };

    // Bind all modules into process space, by the default NT loader.
    // This is a pretty interesting place where you can hook the interface to Windows.
    {
        for ( const PEFile::PEImportDesc& importEntry : calcExec.imports )
        {
            // Load the actual module.
            HMODULE memoryModule = LoadLibraryA( importEntry.DLLName.c_str() );

            assert( memoryModule != NULL );

            // Need to write into the thunk.
            IMAGE_THUNK_DATA *modThunkIter = (IMAGE_THUNK_DATA*)( (char*)imageMemory + importEntry.firstThunkRef.GetRVA() );

            Helpers::InstallImportThunks( memoryModule, modThunkIter, importEntry.funcs );
        }
    }

    // Bind all delay import modules right away.
    {
        for ( const PEFile::PEDelayLoadDesc& delayLoad : calcExec.delayLoads )
        {
            HMODULE modHandle = LoadLibraryA( delayLoad.DLLName.c_str() );

            assert( modHandle != NULL );

            // Write it into memory.
            {
                void *modHandlePtr = ( (char*)imageMemory + delayLoad.DLLHandleAlloc.ResolveOffset( 0 ) );

                *( (HMODULE*)modHandlePtr ) = modHandle;
            }

            // Need to write into the thunk.
            IMAGE_THUNK_DATA *modThunkIter = (IMAGE_THUNK_DATA*)( (char*)imageMemory + delayLoad.IATRef.GetRVA() );

            Helpers::InstallImportThunks( modHandle, modThunkIter, delayLoad.importNames );
        }
    }

    // Set some internal Windows properties.
    {
        // Update internal image base.
        // (https://github.com/sincoder/sinpeloader/blob/master/peloader.cpp)
        PEB *pebInfo = NtCurrentTeb()->ProcessEnvironmentBlock;

        pebInfo->Reserved3[1] = imageMemory;

        // Update the image loader entry.
        // The heroes who figured this out are located at...
        // http://www.rohitab.com/discuss/topic/42335-custom-pe-loader-new-imagebase-puzzle/
        PEB_LDR_DATA *ldrData = pebInfo->Ldr;

        LDR_DATA_TABLE_ENTRY *exeEntry = (LDR_DATA_TABLE_ENTRY*)( (char*)ldrData->InMemoryOrderModuleList.Flink - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) );

        exeEntry->DllBase = imageMemory;

        // TODO: patch more internal things, like full path to executable.
    }

    // Run the executable.
    // By default we are not going to return from that executable.
    // It is another task for the reader to make it actually return.
    {
        typedef void (__stdcall*exeEntryPoint_t)( void );

        exeEntryPoint_t entryp = (exeEntryPoint_t)( (char*)imageMemory + calcExec.peOptHeader.addressOfEntryPointRef.GetRVA() );

        // Into TheGame!!!
        entryp();
    }
    
    // TODO: clean up after ourselves.

    return 0;
}