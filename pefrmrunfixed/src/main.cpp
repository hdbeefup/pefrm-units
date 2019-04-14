#include <peframework.h>

#include <cstdio>
#include <fstream>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#undef ABSOLUTE

// We need special dummy variables.
// Thank you to NTAuthority (bas) and iFarbod for helping.
// (https://github.com/ctnorth/ctnorth/blob/master/Client/Launcher/DummyVariables.cpp)
static constexpr size_t _peFixedBaseOffset = 0x1000;

// This should be the image size that is required by the executable.
// Note that this does NOT match the executable file size, as the executable usually expands to greater size later.
// Has been adjusted to fit the GTA_SA.EXE executable.
static constexpr size_t _peRequiredImageSize = 0x01180000;

#pragma code_seg(push, ".exebuf")
__declspec(allocate(".exebuf")) char exe_loader_buffer[ _peRequiredImageSize - _peFixedBaseOffset ];
#pragma code_seg(pop)

// Create a new code section and merge .text into it, effectively putting the executable code behind our things!
#pragma code_seg(push, ".newexe")
#pragma code_seg(pop)

// Drawback of this method is that it creates a HUGE executable due to MSVC linker behavior.
// If someone finds a way to decrease the executable size it would be highly appreciated.

static constexpr size_t exe_buffer_end = _countof( exe_loader_buffer ) + _peFixedBaseOffset;

int main( int argc, char *argv[] )
{
    // Get our module base address.
    void *ourBase = GetModuleHandleW( nullptr );

    // Verify that our executable buffer is placed alright.
    if ( exe_loader_buffer - _peFixedBaseOffset != ourBase )
    {
        std::cout << "invalid dummy buffer placement (compiler error)" << std::endl;

        return -103;
    }

    // Load the executable file.
    // We are not intercepting any special exceptions so consider it as an excercise for you.
    PEFile fixedExec;
    {
        std::fstream stlFileStream( "fixed.exe", std::ios::binary | std::ios::in );

        if ( !stlFileStream.good() )
        {
            std::cout << "failed to load executable file" << std::endl;

            return -1;
        }

        PEStreamSTL peSTLStream( &stlFileStream );

        // The next call could throw exceptions.

        fixedExec.LoadFromDisk( &peSTLStream );
    }

    // Verify that the executable base address matches our own.
    std::uint64_t imageBase = fixedExec.GetImageBase();

    if ( (void*)imageBase != ourBase )
    {
        std::cout << "loaded executable image base does not match loader image base" << std::endl;

        return -2;
    }

    // Verify our internal buffer is big enough to map the custom executable.
    std::uint32_t imageSize = fixedExec.peOptHeader.sizeOfImage;

    if ( imageSize > exe_buffer_end )
    {
        std::cout << "loaded executable is too big for loader executable buffer (please recompile with bigger buffer)" << std::endl;

        return -3;
    }

    // Make sure there is no section underneath the fixed image offset.
    if ( fixedExec.peOptHeader.baseOfCode < _peFixedBaseOffset )
    {
        std::cout << "loaded executable has code underneath the fixed base offset (invalid)" << std::endl;

        return -4;
    }

    // Make our whole executable buffer RWE-able.
    {
        DWORD oldprot;
        BOOL success = VirtualProtect( exe_loader_buffer, _countof(exe_loader_buffer), PAGE_EXECUTE_READWRITE, &oldprot );

        if ( success != TRUE )
        {
            std::cout << "failed to set full access rights to executable buffer" << std::endl;

            return -5;
        }
    }

    // Verify that the binary matches our platform.
    bool doesMatchMachine = false;

#ifdef _M_IX86
    if ( fixedExec.pe_finfo.machine_id == IMAGE_FILE_MACHINE_I386 )
#elif defined(_M_AMD64)
    if ( fixedExec.pe_finfo.machine_id == IMAGE_FILE_MACHINE_AMD64 )
#else
    if ( false )
#endif
    {
        doesMatchMachine = true;
    }

    if ( !doesMatchMachine )
    {
        std::cout << "cannot run EXE because it is compiled for a different processor\n";

        return -6;
    }

    // We need to run a normal EXE file, not a DLL.
    if ( fixedExec.IsDynamicLinkLibrary() )
    {
        std::cout << "cannot run a DLL file.\n";

        return -7;
    }

    // Map the binary into address space.
    // This is done in a very basic way and it is left up to the reader to improve it.
    {
        for ( auto iter = fixedExec.GetSectionIterator(); !iter.IsEnd(); iter.Increment() )
        {
			PEFile::PESection *theSect = iter.Resolve();

            std::uint32_t virtualAddr = theSect->GetVirtualAddress();

            std::uint32_t dataSize = (std::uint32_t)theSect->stream.Size();

            void *sectMem = ( (char*)ourBase + virtualAddr );

            theSect->stream.Seek( 0 );
            theSect->stream.Read( sectMem, dataSize );
        }
    }

    // We do not have to relocate.

    // Register all exception handlers.
#ifdef _M_AMD64
    {
        for ( const PEFile::PERuntimeFunction& rtFunc : fixedExec.exceptRFs )
        {
            RUNTIME_FUNCTION nativeRTFunc;
            nativeRTFunc.BeginAddress = rtFunc.beginAddrRef.GetRVA();
            nativeRTFunc.EndAddress = rtFunc.endAddrRef.GetRVA();
            nativeRTFunc.UnwindInfoAddress = rtFunc.unwindInfoRef.GetRVA();
            
            BOOLEAN success = RtlAddFunctionTable( &nativeRTFunc, 1, imageBase );

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
                void *funcAddr = nullptr;

                if ( funcInfo.isOrdinalImport )
                {
                    funcAddr = GetProcAddress( memoryModule, (LPCSTR)(WORD)funcInfo.ordinal_hint );
                }
                else
                {
                    funcAddr = GetProcAddress( memoryModule, funcInfo.name.GetConstString() );
                }

                if ( funcAddr == nullptr )
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
        for ( const PEFile::PEImportDesc& importEntry : fixedExec.imports )
        {
            // Load the actual module.
            HMODULE memoryModule = LoadLibraryA( importEntry.DLLName.GetConstString() );

            assert( memoryModule != nullptr );

            // Need to write into the thunk.
            IMAGE_THUNK_DATA *modThunkIter = (IMAGE_THUNK_DATA*)( (char*)ourBase + importEntry.firstThunkRef.GetRVA() );

            Helpers::InstallImportThunks( memoryModule, modThunkIter, importEntry.funcs );
        }
    }

    // Bind all delay import modules right away.
    {
        for ( const PEFile::PEDelayLoadDesc& delayLoad : fixedExec.delayLoads )
        {
            HMODULE modHandle = LoadLibraryA( delayLoad.DLLName.GetConstString() );

            assert( modHandle != nullptr );

            // Write it into memory.
            {
                void *modHandlePtr = ( (char*)ourBase + delayLoad.DLLHandleAlloc.ResolveOffset( 0 ) );

                *( (HMODULE*)modHandlePtr ) = modHandle;
            }

            // Need to write into the thunk.
            IMAGE_THUNK_DATA *modThunkIter = (IMAGE_THUNK_DATA*)( (char*)ourBase + delayLoad.IATRef.GetRVA() );

            Helpers::InstallImportThunks( modHandle, modThunkIter, delayLoad.importNames );
        }
    }

    // Run the executable.
    // By default we are not going to return from that executable.
    // It is another task for the reader to make it actually return.
    {
        typedef void (__stdcall*exeEntryPoint_t)( void );

        exeEntryPoint_t entryp = (exeEntryPoint_t)( (char*)ourBase + fixedExec.peOptHeader.addressOfEntryPointRef.GetRVA() );

        // Into TheGame!!!
        entryp();
    }
    
    // TODO: clean up after ourselves.

    // Success!
    return 0;
}