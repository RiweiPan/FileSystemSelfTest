#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <deque>
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <dirent.h>

#define MD5_BLOCK_SIZE 16

#define log_level 0
#define fsst_debug_log(fmt, ...) \
    do { \
        if(1 <= log_level) { \
            fprintf(stderr, fmt, ##__VA_ARGS__); \
        } \
    } while(0)

class MD5 {
public:
    void calulate(unsigned char *buffer, unsigned long len, unsigned char *fp) {
        MD5_CTX ctx;
        md5_init(&ctx);
        md5_update(&ctx, buffer, len);
        md5_final(&ctx, fp);
    }

    void calculate_file(const char *filename, unsigned char *fp) {
        MD5_CTX ctx;
        md5_init(&ctx);
        FILE *file = fopen(filename, "rb");
        if(file == NULL) {
            return;
        }
        unsigned char buffer[1024];
        size_t len;
        while((len = fread(buffer, 1, 1024, file)) > 0) {
            md5_update(&ctx, buffer, len);
        }
        md5_final(&ctx, fp);
        fclose(file);
    }


    std::string byte_to_hex(unsigned char *byte, int len) {
        std::string hex;
        for(int i = 0; i < len; i++) {
            char buf[3];
            sprintf(buf, "%02x", byte[i]);
            hex.append(buf);
        }
        return hex;
    }

private:

#define ROTLEFT(a,b) ((a << b) | (a >> (32-b)))

#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x ^ y ^ z)
#define I(x,y,z) (y ^ (x | ~z))

#define FF(a,b,c,d,m,s,t) { a += F(b,c,d) + m + t; \
                            a = b + ROTLEFT(a,s); }
#define GG(a,b,c,d,m,s,t) { a += G(b,c,d) + m + t; \
                            a = b + ROTLEFT(a,s); }
#define HH(a,b,c,d,m,s,t) { a += H(b,c,d) + m + t; \
                            a = b + ROTLEFT(a,s); }
#define II(a,b,c,d,m,s,t) { a += I(b,c,d) + m + t; \
                            a = b + ROTLEFT(a,s); }

    typedef struct {
        unsigned char data[64];
        unsigned int datalen;
        unsigned long long bitlen;
        unsigned int state[4];
    } MD5_CTX;

    void md5_transform(MD5_CTX *ctx, unsigned char data[]) {
        unsigned int a, b, c, d, m[16], i, j;

        // MD5 specifies big endian byte order, but this implementation assumes a little
        // endian byte order CPU. Reverse all the bytes upon input, and re-reverse them
        // on output (in md5_final()).
        for (i = 0, j = 0; i < 16; ++i, j += 4)
            m[i] = (data[j]) + (data[j + 1] << 8) + (data[j + 2] << 16) + (data[j + 3] << 24);

        a = ctx->state[0];
        b = ctx->state[1];
        c = ctx->state[2];
        d = ctx->state[3];

        FF(a,b,c,d,m[0],  7,0xd76aa478);
        FF(d,a,b,c,m[1], 12,0xe8c7b756);
        FF(c,d,a,b,m[2], 17,0x242070db);
        FF(b,c,d,a,m[3], 22,0xc1bdceee);
        FF(a,b,c,d,m[4],  7,0xf57c0faf);
        FF(d,a,b,c,m[5], 12,0x4787c62a);
        FF(c,d,a,b,m[6], 17,0xa8304613);
        FF(b,c,d,a,m[7], 22,0xfd469501);
        FF(a,b,c,d,m[8],  7,0x698098d8);
        FF(d,a,b,c,m[9], 12,0x8b44f7af);
        FF(c,d,a,b,m[10],17,0xffff5bb1);
        FF(b,c,d,a,m[11],22,0x895cd7be);
        FF(a,b,c,d,m[12], 7,0x6b901122);
        FF(d,a,b,c,m[13],12,0xfd987193);
        FF(c,d,a,b,m[14],17,0xa679438e);
        FF(b,c,d,a,m[15],22,0x49b40821);

        GG(a,b,c,d,m[1],  5,0xf61e2562);
        GG(d,a,b,c,m[6],  9,0xc040b340);
        GG(c,d,a,b,m[11],14,0x265e5a51);
        GG(b,c,d,a,m[0], 20,0xe9b6c7aa);
        GG(a,b,c,d,m[5],  5,0xd62f105d);
        GG(d,a,b,c,m[10], 9,0x02441453);
        GG(c,d,a,b,m[15],14,0xd8a1e681);
        GG(b,c,d,a,m[4], 20,0xe7d3fbc8);
        GG(a,b,c,d,m[9],  5,0x21e1cde6);
        GG(d,a,b,c,m[14], 9,0xc33707d6);
        GG(c,d,a,b,m[3], 14,0xf4d50d87);
        GG(b,c,d,a,m[8], 20,0x455a14ed);
        GG(a,b,c,d,m[13], 5,0xa9e3e905);
        GG(d,a,b,c,m[2],  9,0xfcefa3f8);
        GG(c,d,a,b,m[7], 14,0x676f02d9);
        GG(b,c,d,a,m[12],20,0x8d2a4c8a);

        HH(a,b,c,d,m[5],  4,0xfffa3942);
        HH(d,a,b,c,m[8], 11,0x8771f681);
        HH(c,d,a,b,m[11],16,0x6d9d6122);
        HH(b,c,d,a,m[14],23,0xfde5380c);
        HH(a,b,c,d,m[1],  4,0xa4beea44);
        HH(d,a,b,c,m[4], 11,0x4bdecfa9);
        HH(c,d,a,b,m[7], 16,0xf6bb4b60);
        HH(b,c,d,a,m[10],23,0xbebfbc70);
        HH(a,b,c,d,m[13], 4,0x289b7ec6);
        HH(d,a,b,c,m[0], 11,0xeaa127fa);
        HH(c,d,a,b,m[3], 16,0xd4ef3085);
        HH(b,c,d,a,m[6], 23,0x04881d05);
        HH(a,b,c,d,m[9],  4,0xd9d4d039);
        HH(d,a,b,c,m[12],11,0xe6db99e5);
        HH(c,d,a,b,m[15],16,0x1fa27cf8);
        HH(b,c,d,a,m[2], 23,0xc4ac5665);

        II(a,b,c,d,m[0],  6,0xf4292244);
        II(d,a,b,c,m[7], 10,0x432aff97);
        II(c,d,a,b,m[14],15,0xab9423a7);
        II(b,c,d,a,m[5], 21,0xfc93a039);
        II(a,b,c,d,m[12], 6,0x655b59c3);
        II(d,a,b,c,m[3], 10,0x8f0ccc92);
        II(c,d,a,b,m[10],15,0xffeff47d);
        II(b,c,d,a,m[1], 21,0x85845dd1);
        II(a,b,c,d,m[8],  6,0x6fa87e4f);
        II(d,a,b,c,m[15],10,0xfe2ce6e0);
        II(c,d,a,b,m[6], 15,0xa3014314);
        II(b,c,d,a,m[13],21,0x4e0811a1);
        II(a,b,c,d,m[4],  6,0xf7537e82);
        II(d,a,b,c,m[11],10,0xbd3af235);
        II(c,d,a,b,m[2], 15,0x2ad7d2bb);
        II(b,c,d,a,m[9], 21,0xeb86d391);

        ctx->state[0] += a;
        ctx->state[1] += b;
        ctx->state[2] += c;
        ctx->state[3] += d;
    }

    void md5_init(MD5_CTX *ctx)
    {
        ctx->datalen = 0;
        ctx->bitlen = 0;
        ctx->state[0] = 0x67452301;
        ctx->state[1] = 0xEFCDAB89;
        ctx->state[2] = 0x98BADCFE;
        ctx->state[3] = 0x10325476;
    }

    void md5_update(MD5_CTX *ctx, unsigned char data[], size_t len)
    {
        size_t i;

        for (i = 0; i < len; ++i) {
            ctx->data[ctx->datalen] = data[i];
            ctx->datalen++;
            if (ctx->datalen == 64) {
                md5_transform(ctx, ctx->data);
                ctx->bitlen += 512;
                ctx->datalen = 0;
            }
        }
    }

    void md5_final(MD5_CTX *ctx, unsigned char hash[])
    {
        size_t i;

        i = ctx->datalen;

        // Pad whatever data is left in the buffer.
        if (ctx->datalen < 56) {
            ctx->data[i++] = 0x80;
            while (i < 56)
                ctx->data[i++] = 0x00;
        }
        else if (ctx->datalen >= 56) {
            ctx->data[i++] = 0x80;
            while (i < 64)
                ctx->data[i++] = 0x00;
            md5_transform(ctx, ctx->data);
            memset(ctx->data, 0, 56);
        }

        // Append to the padding the total message's length in bits and transform.
        ctx->bitlen += ctx->datalen * 8;
        ctx->data[56] = ctx->bitlen;
        ctx->data[57] = ctx->bitlen >> 8;
        ctx->data[58] = ctx->bitlen >> 16;
        ctx->data[59] = ctx->bitlen >> 24;
        ctx->data[60] = ctx->bitlen >> 32;
        ctx->data[61] = ctx->bitlen >> 40;
        ctx->data[62] = ctx->bitlen >> 48;
        ctx->data[63] = ctx->bitlen >> 56;
        md5_transform(ctx, ctx->data);

        // Since this implementation uses little endian byte ordering and MD uses big endian,
        // reverse all the bytes when copying the final state to the output hash.
        for (i = 0; i < 4; ++i) {
            hash[i]      = (ctx->state[0] >> (i * 8)) & 0x000000ff;
            hash[i + 4]  = (ctx->state[1] >> (i * 8)) & 0x000000ff;
            hash[i + 8]  = (ctx->state[2] >> (i * 8)) & 0x000000ff;
            hash[i + 12] = (ctx->state[3] >> (i * 8)) & 0x000000ff;
        }
    }


};

#define FSST_BUFSIZE_MAX 1024 * 1024 * 10 // 10MB
class Shared_Buffers {
public:
    Shared_Buffers() {
        shared_read_buffer = new unsigned char[FSST_BUFSIZE_MAX];
        shared_write_buffer = new unsigned char[FSST_BUFSIZE_MAX];
        memset(shared_read_buffer, 0, FSST_BUFSIZE_MAX);
        memset(shared_write_buffer, 0, FSST_BUFSIZE_MAX);
    }
    ~Shared_Buffers() {
        delete shared_read_buffer;
        delete shared_write_buffer;
    }

    unsigned long parse_buffer_size(std::string strsize) {
        if(isStringDigit(strsize)) {
            return std::stoul(strsize);
        }
        if(endsWith(strsize, 'k') || endsWith(strsize, 'K')) {
            return std::stoul(strsize.substr(0, strsize.size() - 1)) * 1024;
        }
        if(endsWith(strsize, 'm') || endsWith(strsize, 'M')) {
            return std::stoul(strsize.substr(0, strsize.size() - 1)) * 1024 * 1024;
        }
        return 0;
    }

    std::pair<unsigned long, unsigned char*> get_shared_buffer(std::string strsize, int is_read) {
        // fsst_debug_log("Shared_Buffers: get_shared_buffer, size = %s, is_read = %d\n", strsize.c_str(), is_read);
        unsigned long bufsize_inbyte = parse_buffer_size(strsize);
        return std::make_pair(bufsize_inbyte, get_buffer(bufsize_inbyte, is_read));
    }

    std::pair<unsigned long, unsigned char*> get_shared_buffer(unsigned long bufsize_inbyte, int is_read) {
        // fsst_debug_log("Shared_Buffers: get_shared_buffer, size = %lu, is_read = %d\n", bufsize_inbyte, is_read);
        return std::make_pair(bufsize_inbyte, get_buffer(bufsize_inbyte, is_read));
    }

    void init_shared_buffer(unsigned char chdata) {
        memset(shared_read_buffer, chdata, FSST_BUFSIZE_MAX);
        memset(shared_write_buffer, chdata, FSST_BUFSIZE_MAX);
    }
private:
    unsigned char *shared_read_buffer;
    unsigned char *shared_write_buffer;
    bool isStringDigit(const std::string& str) {
        for (char c : str) {
            if (!std::isdigit(c)) {
                return false;
            }
        }
        return true;
    }
    bool endsWith(const std::string& str, char suffix) {
    if (str.empty()) {
        return false;
    }

    return str.back() == suffix;
    }
    unsigned char *get_buffer(unsigned long required_size, int is_read) {
        if(required_size > FSST_BUFSIZE_MAX) {
            return nullptr;
        }
        if(is_read) {
            return shared_read_buffer;
        } else {
            return shared_write_buffer;
        }
    }
};

enum FSST_Command_Type {
    FSST_CMD_CREATE = 0,
    FSST_CMD_OPEN,
    FSST_CMD_CLOSE,
    FSST_CMD_READ,
    FSST_CMD_PREAD,
    FSST_CMD_WRITE,
    FSST_CMD_PWRITE,
    FSST_CMD_FSYNC,
    FSST_CMD_FDATASYNC,
    FSST_CMD_SEEK,
    FSST_CMD_UNLINK,
    FSST_CMD_RENAME,
    FSST_CMD_IOCTL,
    FSST_CMD_PREPARE_FILE,
    FSST_CMD_FILE_MD5,
    FSST_CMD_SLEEP,
    FSST_CMD_CLEARCACHE,
    FSST_CMD_INIT_SHARED_BUFFER,
    FSST_CMD_INIT_RANDOM_ACCESS,
    FSST_CMD_UNKNOWN = -1,
};

std::string get_cmd_name_by_type(enum FSST_Command_Type type) {
    switch(type) {
        case FSST_CMD_CREATE:
            return "create";
        case FSST_CMD_OPEN:
            return "open";
        case FSST_CMD_CLOSE:
            return "close";
        case FSST_CMD_READ:
            return "read";
        case FSST_CMD_PREAD:
            return "pread";
        case FSST_CMD_WRITE:
            return "write";
        case FSST_CMD_PWRITE:
            return "pwrite";
        case FSST_CMD_FSYNC:
            return "fsync";
        case FSST_CMD_FDATASYNC:
            return "fdatasync";
        case FSST_CMD_SEEK:
            return "seek";
        case FSST_CMD_UNLINK:
            return "unlink";
        case FSST_CMD_RENAME:
            return "rename";
        case FSST_CMD_IOCTL:
            return "ioctl";
        case FSST_CMD_PREPARE_FILE:
            return "prepare_file";
        case FSST_CMD_FILE_MD5:
            return "file_md5";
        case FSST_CMD_SLEEP:
            return "sleep";
        case FSST_CMD_CLEARCACHE:
            return "clearcache";
        case FSST_CMD_INIT_SHARED_BUFFER:
            return "init_shared_buffer";
        case FSST_CMD_INIT_RANDOM_ACCESS:
            return "init_random_access";
        default:
            return "unknown";
    }
}

class FSST_Command {
public:
    FSST_Command(FSST_Command_Type type, std::vector<std::string> args, bool is_eval) {
        this->type = type;
        this->args = args;
        this->do_eval = is_eval;
        ret_val = 0;
    }
    void set_eval(bool is_eval) {
        do_eval = is_eval;
    }
    enum FSST_Command_Type type;
    bool do_eval;
    virtual bool parse(long arg) = 0;
    virtual bool run(long arg, long arg2) = 0;
    virtual long return_value() = 0;
    virtual std::string eval_value() = 0;
protected:
    long ret_val;
    std::vector<std::string> args;
};


class FSST_CreateCmd : public FSST_Command {
public:
    FSST_CreateCmd(std::string runDir, Shared_Buffers *sb, std::vector<std::string> args, bool is_eval) : FSST_Command(FSST_CMD_CREATE, args, is_eval) {
        this->runDir = runDir;
    }
    bool parse(long arg) override {
        if(args.size() != 1) 
            return false;
        __filename = runDir + "/" + args[0];
        return true; 
    }
    bool run(long arg, long arg2) override {
        fsst_debug_log("FSST_CreateCmd: create file %s\n", __filename.c_str());
        int fd = open(__filename.c_str(), O_RDWR | O_CREAT, 0666);
        if(fd < 0) {
            std::cerr << "Failed to create file: " << __filename << ", fd = " << fd << std::endl;
            return false;
        }
        ret_val = fd;
        return true; 
    }
    long return_value() override { return ret_val; }
    std::string eval_value() override { 
        return std::to_string(ret_val);
    }
private:
    std::string runDir;
    std::string __filename;
};

class FSST_OpenCmd : public FSST_Command {
public:
    FSST_OpenCmd(std::string runDir, Shared_Buffers *sb, std::vector<std::string> args, bool is_eval) : FSST_Command(FSST_CMD_OPEN, args, is_eval) {
        this->runDir = runDir;
    }
    bool parse(long arg) override {
        if(args.size() != 1) 
            return false;
        __filename = runDir + "/" + args[0];
        return true; 
    }
    bool run(long arg, long arg2) override {
        fsst_debug_log("FSST_OpenCmd: open file %s\n", __filename.c_str());
        int fd = open(__filename.c_str(), O_RDWR, 0666);
        if(fd < 0) 
            return false;
        ret_val = fd;
        return true; 
    }
    long return_value() override { return ret_val; }
    std::string eval_value() override { 
        return std::to_string(ret_val);
    }
private:
    std::string runDir;
    std::string __filename;
};

class FSST_CloseCmd : public FSST_Command {
public:
    FSST_CloseCmd(std::string runDir, Shared_Buffers *sb, std::vector<std::string> args, bool is_eval) : FSST_Command(FSST_CMD_CLOSE, args, is_eval) {}
    bool parse(long arg) override {
        return true; 
    }
    bool run(long __fd, long arg2) override {
        fsst_debug_log("FSST_CloseCmd: close fd = %ld\n", __fd);
        int ret = close(__fd);
        if(ret < 0) 
            return false;
        ret_val = ret;
        return true; 
    }
    long return_value() override { return ret_val; }
    std::string eval_value() override { 
        return std::to_string(ret_val);
    }
};

class FSST_ReadCmd : public FSST_Command {
public:
    FSST_ReadCmd(std::string runDir, Shared_Buffers *sb, std::vector<std::string> args, bool is_eval) : FSST_Command(FSST_CMD_READ, args, is_eval) {
        this->sb = sb;
    }
    bool parse(long arg) override {
        if(args.size() != 1) 
            return false;
        std::pair<unsigned long, unsigned char*> pair = sb->get_shared_buffer(args[0], 1);
        __size = pair.first;
        __buf = pair.second;
        if(__buf == nullptr) {
            return false;
        }
        return true; 
    }

    bool run(long __fd, long arg2) override {
        fsst_debug_log("FSST_ReadCmd: read fd = %ld, size = %d\n", __fd, __size);
        ssize_t ret = read(__fd, __buf, __size);
        if(ret < 0) 
            return false;
        ret_val = ret;
        return true; 
    }
    long return_value() override { return ret_val; }
    std::string eval_value() override {
        MD5 md5;
        unsigned char hash[MD5_BLOCK_SIZE];
        md5.calulate(__buf, __size, hash);
        std::string md5_str = md5.byte_to_hex(hash, MD5_BLOCK_SIZE);
        return md5_str;
    }
private:
    int __size;
    unsigned char *__buf;
    Shared_Buffers *sb;
};

class FSST_PreadCmd : public FSST_Command {
public:
    FSST_PreadCmd(std::string runDir, Shared_Buffers *sb, std::vector<std::string> args, bool is_eval) : FSST_Command(FSST_CMD_PREAD, args, is_eval) {
        this->sb = sb;
    }
    bool parse(long max_file_size) override {
        if(args.size() != 2) 
            return false;
        std::pair<unsigned long, unsigned char*> pair = sb->get_shared_buffer(args[0], 1);
        __size = pair.first;
        __buf = pair.second;
        if(__buf == nullptr) {
            return false;
        }
        if(args[1] == "X") {
            __offset = 0;
        } else {
            __offset = std::stoi(args[1]);
        }
        return true; 
    }
    bool run(long __fd, long __max_access_range) override {
        if(__max_access_range > 0)
            __offset = rand() % (__max_access_range - __size - 1);
        fsst_debug_log("FSST_PreadCmd: pread fd = %ld, size = %d, offset = %d\n", __fd, __size, __offset);
        ssize_t ret = pread(__fd, __buf, __size, __offset);
        if(ret < 0) 
            return false;
        ret_val = ret;
        return true; 
    }
    long return_value() override { return ret_val; }
    std::string eval_value() override {
        MD5 md5;
        unsigned char hash[MD5_BLOCK_SIZE];
        md5.calulate(__buf, __size, hash);
        std::string md5_str = md5.byte_to_hex(hash, MD5_BLOCK_SIZE);
        return md5_str;
    }
private:
    int __size;
    unsigned char *__buf;
    unsigned long __offset;
    Shared_Buffers *sb;
};

class FSST_WriteCmd : public FSST_Command {
public:
    FSST_WriteCmd(std::string runDir, Shared_Buffers *sb, std::vector<std::string> args, bool is_eval) : FSST_Command(FSST_CMD_WRITE, args, is_eval) {
        this->sb = sb;
    }
    bool parse(long arg) override {
        if(args.size() != 1) 
            return false;
        std::pair<unsigned long, unsigned char*> pair = sb->get_shared_buffer(args[0], 1);
        __size = pair.first;
        __buf = pair.second;
        if(__buf == nullptr) {
            return false;
        }
        return true; 
    }
    bool run(long __fd, long arg2) override {
        fsst_debug_log("FSST_WriteCmd: write fd = %ld, size = %d\n", __fd, __size);
        ssize_t ret = write(__fd, __buf, __size);
        if(ret < 0) {
            perror("write");
            std::cerr << "FSST_WriteCmd: write failed, ret = " <<  ret << std::endl;
            return false;
        }
        ret_val = ret;
        return true; 
    }
    long return_value() override { return ret_val; }
    std::string eval_value() override { 
        return std::string(std::to_string(ret_val)); 
    }
private:
    int __size;
    unsigned char *__buf;
    Shared_Buffers *sb;
};

class FSST_PwriteCmd : public FSST_Command {
public:
    FSST_PwriteCmd(std::string runDir, Shared_Buffers *sb, std::vector<std::string> args, bool is_eval) : FSST_Command(FSST_CMD_PWRITE, args, is_eval) {
        this->sb = sb;
    }
    bool parse(long arg) override {
        if(args.size() != 2) 
            return false;
        std::pair<unsigned long, unsigned char*> pair = sb->get_shared_buffer(args[0], 0);
        __size = pair.first;
        __buf = pair.second;
        if(__buf == nullptr) {
            return false;
        }
        if(args[1] == "X") {
            __offset = 0;
        } else {
            __offset = std::stoi(args[1]);
        }
        return true; 
    }
    bool run(long __fd, long __max_access_range) override {
        if(__max_access_range > 0)
            __offset = rand() % (__max_access_range - __size - 1);
        fsst_debug_log("FSST_PwriteCmd: pwrite fd = %ld, size = %d, offset = %d\n", __fd, __size, __offset);
        ssize_t ret = pwrite(__fd, __buf, __size, __offset);
        if(ret < 0) 
            return false;
        ret_val = ret;
        return true; 
    }
    long return_value() override { return ret_val; }
    std::string eval_value() override { 
        return std::to_string(ret_val);
    }
private:
    int __size;
    unsigned char *__buf;
    unsigned long __offset;
    Shared_Buffers *sb;
};

class FSST_FsyncCmd : public FSST_Command {
public:
    FSST_FsyncCmd(std::string runDir, Shared_Buffers *sb, std::vector<std::string> args, bool is_eval) : FSST_Command(FSST_CMD_FSYNC, args, is_eval) {}
    bool parse(long arg) override {
        return true; 
    }
    bool run(long __fd, long arg2) override {
        fsst_debug_log("FSST_FsyncCmd: fsync fd = %ld\n", __fd);
        int ret = fsync(__fd);
        if(ret < 0) 
            return false;
        ret_val = ret;
        return true; 
    }
    long return_value() override { return ret_val; }
    std::string eval_value() override { 
        return std::to_string(ret_val);
    }
};

class FSST_FdatasyncCmd : public FSST_Command {
public:
    FSST_FdatasyncCmd(std::string runDir, Shared_Buffers *sb, std::vector<std::string> args, bool is_eval) : FSST_Command(FSST_CMD_FDATASYNC, args, is_eval) {}
    bool parse(long arg) override {
        return true; 
    }
    bool run(long __fd, long arg2) override {
        fsst_debug_log("FSST_FdatasyncCmd: fdatasync fd = %ld\n", __fd);
        int ret = fdatasync(__fd);
        if(ret < 0) 
            return false;
        ret_val = ret;
        return true; 
    }
    long return_value() override { return ret_val; }
    std::string eval_value() override { 
        return std::to_string(ret_val);
    }
};

class FSST_SeekCmd : public FSST_Command {
public:
    FSST_SeekCmd(std::string runDir, Shared_Buffers *sb, std::vector<std::string> args, bool is_eval) : FSST_Command(FSST_CMD_SEEK, args, is_eval) {}
    bool parse(long arg) override {
        if(args.size() != 1) 
            return false;
        __offset = std::stol(args[0]);
        return true; 
    }
    bool run(long __fd, long arg2) override {
        fsst_debug_log("FSST_SeekCmd: seek fd = %ld, offset = %d\n", __fd, __offset);
        off_t ret = lseek(__fd, __offset, SEEK_SET);
        if(ret < 0) 
            return false;
        ret_val = ret;
        return true; 
    }
    long return_value() override { return ret_val; }
    std::string eval_value() override { 
        return std::to_string(ret_val);
    }
private:
    unsigned long __offset;
};

class FSST_RenameCmd : public FSST_Command {
public:
    FSST_RenameCmd(std::string runDir, Shared_Buffers *sb, std::vector<std::string> args, bool is_eval) : FSST_Command(FSST_CMD_RENAME, args, is_eval) {
        this->runDir = runDir;
    }
    bool parse(long arg) override {
        if(args.size() == 2 || args.size() == 3) {
            __oldname = runDir + "/" + args[0];
            __newname = runDir + "/" + args[1];
            rflag = 0;
            if(args.size() == 3)
                rflag = std::stoi(args[2]);
            return true; 
        } else {
            return false;
        }
    }
    bool run(long arg, long arg2) override {
        fsst_debug_log("FSST_RenameCmd: rename %s to %s, flag = %d\n", __oldname.c_str(), __newname.c_str(), rflag);
        int ret = syscall(SYS_renameat2, AT_FDCWD, __oldname.c_str(), AT_FDCWD, __newname.c_str(), rflag);
        if(ret < 0) 
            return false;
        ret_val = ret;
        return true;
    }
    long return_value() override { return ret_val; }
    std::string eval_value() override { 
        return std::to_string(ret_val);
    }
private:
    std::string runDir;
    std::string __oldname;
    std::string __newname;
    int rflag;
};

class FSST_SleepCmd : public FSST_Command {
public:
    FSST_SleepCmd(std::string runDir, Shared_Buffers *sb, std::vector<std::string> args, bool is_eval) : FSST_Command(FSST_CMD_SLEEP, args, is_eval) {}
    bool parse(long arg) override {
        if(args.size() != 1) 
            return false;
        __time = std::stoi(args[0]);
        return true; 
    }
    bool run(long arg, long arg2) override {
        fsst_debug_log("FSST_SleepCmd: sleep %d\n", __time);
        sleep(__time);
        return true; 
    }
    long return_value() override { return 0; }
    std::string eval_value() override { 
        return std::to_string(0);
    }
private:
    int __time;
};

class FSST_PrepareFileCmd : public FSST_Command {
public:
    FSST_PrepareFileCmd(std::string runDir, Shared_Buffers *sb,std::vector<std::string> args, bool is_eval) : FSST_Command(FSST_CMD_PREPARE_FILE, args, is_eval) {
        this->rundir = runDir;
        this->sb = sb;
    }
    bool parse(long arg) override {
        if(args.size() != 2) 
            return false;
        __filename = rundir + "/" + args[0];
        __size = sb->parse_buffer_size(args[1]);
        return true; 
    }
    bool run(long arg, long arg2) override {
        fsst_debug_log("FSST_PrepareFileCmd: prepare file %s, size = %d\n", __filename.c_str(), __size);
        size_t ret;
        int fd = open(__filename.c_str(), O_RDWR | O_CREAT, 0644);
        if(fd < 0) 
            return false;
        const unsigned long bufsize = 512 * 1024;
        unsigned long bufcnt = (__size + bufsize - 1) / bufsize;
        unsigned long remain = __size;
        std::pair<unsigned long, unsigned char*> pair = sb->get_shared_buffer(bufsize, 1);
        __buf = pair.second;
        if(__buf == nullptr) {
            close(fd);
            return false;
        }

        while(remain > 0) {
            ret = write(fd, __buf, (remain > bufsize) ? bufsize : remain);
            if(ret < 0) {
                close(fd);
                return false;
            }
            remain -= ret;
        }
        fsync(fd);
        close(fd);
        return true; 
    }
    long return_value() override { return 0; }
    std::string eval_value() override {
        // check file size
        struct stat st;
        stat(__filename.c_str(), &st);
        return std::to_string(st.st_size);
    }
private:
    Shared_Buffers *sb;
    std::string rundir;
    std::string __filename;
    int __size;
    unsigned char *__buf;
};

class FSST_FileMd5Cmd : public FSST_Command {
public:
    FSST_FileMd5Cmd(std::string runDir, Shared_Buffers *sb,std::vector<std::string> args, bool is_eval) : FSST_Command(FSST_CMD_FILE_MD5, args, is_eval) {
        this->rundir = runDir;
    }
    bool parse(long arg) override {
        if(args.size() != 1) 
            return false;
        __filename = rundir + "/" + args[0];
        return true; 
    }
    bool run(long arg, long arg2) override {
        fsst_debug_log("FSST_FileMd5Cmd: calculate md5 for file %s\n", __filename.c_str());
        MD5 md5;
        unsigned char hash[MD5_BLOCK_SIZE];
        md5.calculate_file(__filename.c_str(), hash);
        __md5 = md5.byte_to_hex(hash, MD5_BLOCK_SIZE);
        fsst_debug_log("FSST_FileMd5Cmd: md5 = %s\n", __md5.c_str());
        return true; 
    }
    long return_value() override { return 0; }
    std::string eval_value() override {
        return __md5;
    }
private:
    std::string rundir;
    std::string __filename;
    std::string __md5;
};

class FSST_ClearCacheCmd : public FSST_Command {
public:
    FSST_ClearCacheCmd(std::string runDir, Shared_Buffers *sb,std::vector<std::string> args, bool is_eval) : FSST_Command(FSST_CMD_CLEARCACHE, args, is_eval) {}
    bool parse(long arg) override {
        return true; 
    }
    bool run(long arg, long arg2) override {
        fsst_debug_log("FSST_ClearCacheCmd: clear cache\n");
        system("sync; echo 3 > /proc/sys/vm/drop_caches"); // sync; echo 3 > /proc/sys/vm/drop_caches
        return true; 
    }
    long return_value() override { return 0; }
    std::string eval_value() override { 
        return std::to_string(0);
    }
};

class FSST_InitSharedBufferCmd : public FSST_Command {
public:
    FSST_InitSharedBufferCmd(std::string runDir, Shared_Buffers *sb,std::vector<std::string> args, bool is_eval) : FSST_Command(FSST_CMD_INIT_SHARED_BUFFER, args, is_eval) {
        this->sb = sb;
    }
    bool parse(long arg) override {
        if(args.size() != 1) 
            return false;
        chdata = args[0].at(0);
        return true; 
    }
    bool run(long arg, long arg2) override {
        fsst_debug_log("FSST_InitSharedBufferCmd: init shared buffer, char = %c\n", chdata);
        sb->init_shared_buffer(chdata);
        return true;
    }
    long return_value() override { return 0; }
    std::string eval_value() override { 
        return std::to_string(0);
    }
private:
    Shared_Buffers *sb;
    char chdata;
};

class FSST_InitRandomAccess : public FSST_Command {
public:
    FSST_InitRandomAccess(std::string runDir, Shared_Buffers *sb,std::vector<std::string> args, bool is_eval) : FSST_Command(FSST_CMD_INIT_RANDOM_ACCESS, args, is_eval) {}
    bool parse(long arg) override {
        if(args.size() != 1) 
            return false;
        seed = std::stoul(args[0]);
        max_access_range = 0;
        return true; 
    }
    bool run(long __fd, long arg2) override {
        fsst_debug_log("FSST_INIT_RANDOM_SEED: init random seed\n");
        struct stat st;
        srand(seed);
        if(fstat(__fd, &st) == 0) {
            max_access_range = st.st_size;
        }
        return true;
    }
    long return_value() override { return max_access_range; }
    std::string eval_value() override { 
        return std::to_string(0);
    }
private:
    unsigned long seed;
    unsigned long max_access_range;
};

class FSST_Task {
public:
    std::string testcase_name;
    std::string running_dir;
    std::string description;
    FSST_Task(std::string testcase_name, std::string running_dir) {
        this->testcase_name = testcase_name;
        this->running_dir = running_dir;
        this->sb = new Shared_Buffers();
    }
    ~FSST_Task() {
        for(int i = 0; i < run_command_list.size(); i++) {
            delete run_command_list[i];
        }
        for(int i = 0; i < pre_command_list.size(); i++) {
            delete pre_command_list[i];
        }
        delete sb;
    }

    bool run_testcase() {
        bool ret = false;
        parse();
        std::cout << "====================================================================" << std::endl;
        std::cout << "[Test Case]:   " << testcase_name << std::endl;
        std::cout << "[Description]: " << description << std::endl;
        ret = run_commands(pre_command_list);
        if(!ret) {
            std::cout << "[Result]:      " << "FAIL" << std::endl;
            return false;
        }
        ret = run_commands(run_command_list);
        if(!ret) {
            std::cout << "[Result]:      " << "FAIL" << std::endl;
            return false;
        }
        ret = evaluate_outputs();
        if(ret) {
            std::cout << "[Result]:      " << "PASS" << std::endl;
        } else {
            std::cout << "[Result]:      " << "FAIL" << std::endl;
        }
        return ret;
    }

private:
    bool is_rand_access = false;
    FSST_Command *parse_cmd(std::string &ops_cmd, std::vector<std::string> &args) {
        FSST_Command *cmd = nullptr;
        if(ops_cmd == "create") {
            cmd = new FSST_CreateCmd(this->running_dir, this->sb, args, false);
        } else if(ops_cmd == "open") { // 增加加入eval?
            cmd = new FSST_OpenCmd(this->running_dir, this->sb, args, false);
        } else if(ops_cmd == "close") {
            cmd = new FSST_CloseCmd(this->running_dir, this->sb, args, false);
        } else if(ops_cmd == "read") {
            cmd = new FSST_ReadCmd(this->running_dir, this->sb, args, false);
        } else if(ops_cmd == "pread") {
            cmd = new FSST_PreadCmd(this->running_dir, this->sb, args, false);
        } else if(ops_cmd == "pwrite") {
            cmd = new FSST_PwriteCmd(this->running_dir, this->sb, args, false);
        } else if(ops_cmd == "lseek") {
            cmd = new FSST_SeekCmd(this->running_dir, this->sb, args, false);
        } else if(ops_cmd == "write") {
            cmd = new FSST_WriteCmd(this->running_dir, this->sb, args, false);
        } else if(ops_cmd == "fsync") {
            cmd = new FSST_FsyncCmd(this->running_dir, this->sb, args, false);
        } else if(ops_cmd == "fdatasync") {
            cmd = new FSST_FdatasyncCmd(this->running_dir, this->sb, args, false);
        } else if(ops_cmd == "rename") {
            cmd = new FSST_RenameCmd(this->running_dir, this->sb, args, false);
        } else if(ops_cmd == "clear-cache") {
            cmd = new FSST_ClearCacheCmd(this->running_dir, this->sb, args, false);
        } else if(ops_cmd == "sleep") {
            cmd = new FSST_SleepCmd(this->running_dir, this->sb, args, false);
        } else if(ops_cmd == "prepare-file") {
            cmd = new FSST_PrepareFileCmd(this->running_dir, this->sb, args, false);
        } else if(ops_cmd == "file-md5") {
            cmd = new FSST_FileMd5Cmd(this->running_dir, this->sb, args, false);
        } else if(ops_cmd == "init-buffer") {
            cmd = new FSST_InitSharedBufferCmd(this->running_dir, this->sb, args, false);
        } else if(ops_cmd == "init-rand-access") {
            cmd = new FSST_InitRandomAccess(this->running_dir, this->sb, args, false);
            is_rand_access = true;
        } else {
            std::cerr << "Unknown command: " << ops_cmd << std::endl;
        }
        return cmd;
    }

    bool parse() {
        std::ifstream file(testcase_name);
        if (!file) {
            std::cerr << "Cannot open file: " << testcase_name << std::endl;
            return false;
        }
        std::string line;

        /**
         * state = 0: initial begin
         * state = 1: pre run
         * state = 2: run
         * state = 3: expected value
         */
        int state = 0;
        while (std::getline(file, line)) {
            // std::cout << line << std::endl;
            if(line.size() == 0 || line.at(0) == '#' || is_blank_line(line)) {
                continue;
            }
            fsst_debug_log("FSST_Task: line = %s, state = %d\n", line.c_str(), state);
            if (line.find("description") != std::string::npos) {
                this->description.assign(line.substr(line.find("=") + 1));
                continue;
            }

            if (line.find("pre-begin") != std::string::npos) {
                state = 1;
                continue;
            }

            if (line.find("pre-end") != std::string::npos) {
                state = 0;
                continue;
            }

            if (line.find("run-begin") != std::string::npos) {
                state = 2;
                continue;
            }

            if (line.find("run-end") != std::string::npos) {
                state = 0;
                continue;
            }

            if (line.find("eval-begin") != std::string::npos) {
                state = 3;
                continue;
            }

            if (line.find("eval-end") != std::string::npos) {
                state = 0;
                continue;
            }

            if(state == 1 || state == 2) {
                std::vector<std::string> args;
                std::stringstream ss(line);
                std::string ops_cmd;
                std::string token;
                bool skip_first = true;
                bool is_eval = false;
                int repeat_times = 1;
                while(ss >> token) {
                    if(skip_first) {
                        if(token == "eval") {
                            is_eval = true;
                            continue;
                        }
                        if(token.find("repeat") != std::string::npos) { // repeat-100
                            repeat_times = std::stoi(token.substr(7));
                            continue;
                        }
                        ops_cmd = token;
                        skip_first = false;
                        continue;
                    }
                    if(token.at(0) == '#')
                        break;
                    args.push_back(token);
                }
                for(int i = 0; i < repeat_times; i++) {
                    FSST_Command *cmd = parse_cmd(ops_cmd, args);
                    if(cmd != nullptr) {
                        cmd->parse(0);
                        if(state == 1) {
                            pre_command_list.push_back(cmd);
                        } else {
                            if(is_eval) {
                                cmd->set_eval(true);
                            }
                            run_command_list.push_back(cmd);
                        }
                    }
                }
            } else if(state == 3) {
                std::vector<std::string> args;
                std::stringstream ss(line);
                std::string token;
                int repeat_times = 1;
                while(ss >> token) {
                    if(token.at(0) == '#')
                        break;
                    if(token.find("repeat") != std::string::npos) { // repeat-100
                        repeat_times = std::stoi(token.substr(7));
                        continue;
                    }
                    args.push_back(token);
                }
                for(int i = 0; i < repeat_times; i++) {
                    expected_output_list.push_back(args[0]);
                }
            }

        }
        return true;
    }

    bool run_commands(std::vector<FSST_Command *> &command_list) {
        int fd = -1;
        unsigned long max_access_range = 0;
        for(int i = 0; i < command_list.size(); i++) {
            FSST_Command *cmd = command_list[i];
            if(cmd->type == FSST_CMD_CREATE) {
                fsst_debug_log("FSST_Task: create file\n");
                if(!cmd->run(0, 0)) {
                    std::cerr << "create failed" << std::endl;
                    return false;
                }
                fd = cmd->return_value();
            } else if(cmd->type == FSST_CMD_OPEN) {
                if(!cmd->run(fd, 0)) {
                    std::cerr << "open failed" << std::endl;
                    return false;
                }
                fd = cmd->return_value();
            } else if(cmd->type == FSST_CMD_CLOSE) {
                if(!cmd->run(fd, 0)) {
                    std::cerr << "close failed" << std::endl;
                    return false;
                }
                fd = -1;
            } else if(cmd->type == FSST_CMD_INIT_RANDOM_ACCESS) {
                if(fd < 0) {
                    std::cerr << "file not opened" << std::endl;
                    return false;
                }
                if(!cmd->run(fd, 0)) {
                    std::cerr << "init random access failed" << std::endl;
                    return false;
                }
                max_access_range = cmd->return_value();
            } else if(cmd->type == FSST_CMD_READ || cmd->type == FSST_CMD_WRITE || cmd->type == FSST_CMD_FSYNC || cmd->type == FSST_CMD_FDATASYNC || 
                cmd->type == FSST_CMD_PREAD || cmd->type == FSST_CMD_PWRITE || cmd->type == FSST_CMD_SEEK || cmd->type == FSST_CMD_IOCTL) {
                if(fd < 0) {
                    std::cerr << "file not opened" << std::endl;
                    return false;
                }
                if(is_rand_access && (cmd->type == FSST_CMD_PREAD || cmd->type == FSST_CMD_PWRITE)) {
                    if(!cmd->run(fd, max_access_range)) {
                        std::cerr << "randome access command failed, type = " << cmd->type << std::endl;
                        return false;
                    }
                } else {
                    if(!cmd->run(fd, 0)) {
                        std::cerr << "command failed, type = " << cmd->type << std::endl;
                        return false;
                    }
                }

            } else {
                if(!cmd->run(0, 0)) {
                    std::cerr << "command failed, type = " << cmd->type << std::endl;
                    return false;
                }            
            }
            if(cmd->do_eval) {
                command_output_list.push_back(cmd);
            }
        }
        return true;
    }

    bool evaluate_outputs() {
        bool is_success = true;
        if(command_output_list.size() != expected_output_list.size()) {
            std::cerr << "output size not match, expected = " << expected_output_list.size() << ", output = " << command_output_list.size() << std::endl;
            return false;
        }
        for(int i = 0; i < command_output_list.size(); i++) {
            if(command_output_list[i]->eval_value() != expected_output_list[i]) {
                std::cerr << "[" << i << "] " << get_cmd_name_by_type(command_output_list[i]->type) 
                    << ": output not match, expected = " << expected_output_list[i] << ", output = " << command_output_list[i]->eval_value() << std::endl;
                is_success = false;
            }
        }
        return is_success;
    }

    Shared_Buffers *sb;
    std::vector<FSST_Command *> pre_command_list;
    std::vector<FSST_Command *> run_command_list;
    std::vector<FSST_Command *> command_output_list;
    std::vector<std::string> expected_output_list;
    bool is_blank_line(std::string &line) {
        size_t len = line.size();
        for(int i = 0; i < len; i++) {
            if(!std::isspace(static_cast<unsigned char>(line.at(i)))) {
                return false;
            }
        }
        return true;
    }

};

class FSST {
public:

    FSST(const std::string testDir, const std::string runningDir) : FSST(0, testDir, runningDir) {}

    FSST(unsigned long seed, const std::string testDir, const std::string runningDir) {
        this->seed = seed;
        this->testDir = testDir; // test case dir
        this->runningDir = runningDir; // running dir
    }

    ~FSST() {

    }

    void traverseDirectory(const std::string& directoryPath) {
        DIR* dir = opendir(directoryPath.c_str());
        if (dir == nullptr) {
            std::cerr << "Error opening directory: " << strerror(errno) << std::endl;
            return;
        }

        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            std::string filePath = directoryPath + "/" + std::string(entry->d_name);
            struct stat fileStat;
            if (stat(filePath.c_str(), &fileStat) == -1) {
                std::cerr << "Error getting file stat: " << strerror(errno) << std::endl;
                continue;
            }

            if (S_ISDIR(fileStat.st_mode)) {
                traverseDirectory(filePath); // Recursive call for subdirectory
            } else if (S_ISREG(fileStat.st_mode) && filePath.find(".fsst") != std::string::npos) {
                test_case_vector.push_back(filePath);
            }
        }
        closedir(dir);
    }
 
    void run_tests() {
        traverseDirectory(testDir);
        int success_cnt = 0;
        for(int i = 0; i < test_case_vector.size(); i++) {
            FSST_Task task(test_case_vector[i], runningDir);
            if(task.run_testcase()) {
                success_cnt++;
            }
        }
        std::cout << "====================================================================" << std::endl;
        std::cout << "Total test cases: " << test_case_vector.size() << ", success: " << success_cnt << ", fail: " << test_case_vector.size() - success_cnt << std::endl;
        std::cout << "====================================================================" << std::endl;
    }

    void run_test_case(std::string case_id) {
        traverseDirectory(testDir);
        for(int i = 0; i < test_case_vector.size(); i++) {
            if(test_case_vector[i].find(case_id) != std::string::npos) {
                FSST_Task task(test_case_vector[i], runningDir);
                task.run_testcase();
                return;
            }
        }
        std::cerr << "test case not found." << std::endl;
    }

private:
    unsigned long seed;
    std::string testDir;
    std::string runningDir;
    std::vector<std::string> test_case_vector;
};

class FSST_Config {
public:
    FSST_Config() {
        testDir = "fsst_testsuit";
    }
    FSST_Config(std::string testDir, std::string runningDir) {
        this->testDir = testDir;
        this->runningDir = runningDir;
    }
    std::string testDir;
    std::string runningDir;
    std::string testcase_id;
};

FSST_Config parse_fsst_args(int argc, char *argv[]) {
    FSST_Config fc;
    char ch;
    while((ch = getopt(argc, argv, "t:r:c:")) != -1) {
        switch(ch) {
            case 't':
                fc.testDir = optarg;
                break;
            case 'r':
                fc.runningDir = optarg;
                break;
            case 'c':
                fc.testcase_id = optarg;
                break;
            default:
                break;
        }
    }
    return fc;
}

int main(int argc, char *argv[]) {
    FSST_Config fc = parse_fsst_args(argc, argv);
    FSST fsst(fc.testDir, fc.runningDir);
    if(fc.runningDir.size() == 0) {
        std::cerr << "running dir not set." << std::endl;
        return -1;
    }
    if(fc.testcase_id.size() > 0) {
        fsst.run_test_case(fc.testcase_id);
    } else {
        fsst.run_tests();
    }
    return 0;
}

