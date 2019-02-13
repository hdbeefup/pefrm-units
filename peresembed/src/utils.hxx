#ifndef _UTILITIES_HEADER_
#define _UTILITIES_HEADER_

#include <peframework.h>
#include <CFileSystem.h>

struct PEStreamFS final : public PEStream
{
    inline PEStreamFS( CFile *useFile ) : useFile( useFile )
    {
        return;
    }

    size_t Read( void *buf, size_t readCount ) override
    {
        return useFile->Read( buf, 1, readCount );
    }

    bool Write( const void *buf, size_t writeCount ) override
    {
        return ( useFile->Write( buf, 1, writeCount ) == writeCount );
    }

    bool Seek( pe_file_ptr_t seek ) override
    {
        return ( useFile->SeekNative( seek, SEEK_SET ) == 0 );
    }

    pe_file_ptr_t Tell( void ) const override
    {
        return useFile->TellNative();
    }

private:
    CFile *useFile;
};

#endif //_UTILITIES_HEADER_