/* Explicit little-endian data decoders. Not a reader, installer or entry. */
#include "runtime_stage0_records.h"
#include <limits.h>
#include <string.h>

_Static_assert(CHAR_BIT == 8, "unsupported byte ABI");

static uint64_t little(const unsigned char *p, unsigned int n)
{
    uint64_t v = 0;
    for (unsigned int j = 0; j < n; ++j) v |= (uint64_t)p[j] << (8*j);
    return v;
}
static int all_zero(const unsigned char *p, size_t n)
{
    unsigned char v = 0;
    for (size_t j = 0; j < n; ++j) v |= p[j];
    return v == 0;
}
static int overlap(const void *a, size_t an, const void *b, size_t bn)
{
    uintptr_t av = (uintptr_t)a, bv = (uintptr_t)b;
    return av <= bv ? bv-av < an : av-bv < bn;
}
static int header(const unsigned char *p, const char *magic)
{
    return memcmp(p,magic,8)==0 && little(p+8,4)==1 && little(p+12,4)==0;
}
static int image(const unsigned char *root, const unsigned char *salt,
                 uint64_t data, uint64_t hashes, uint64_t maximum,
                 struct rnr_stage0_image_record *out)
{
    uint64_t level = data, total = 0;
    if (all_zero(root,32) || all_zero(salt,32) || data < 2 || data > maximum)
        return -1;
    do {
        level = (level + 127) / 128;
        total += level;
    } while (level > 1);
    if (hashes != total) return -1;
    memcpy(out->root,root,32); memcpy(out->salt,salt,32);
    out->data_blocks = data; out->hash_blocks = hashes;
    return 0;
}
static int boot_uuid(const unsigned char *raw)
{
    int nonzero = 0;
    for (unsigned int i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (raw[i] != '-') return -1;
        } else {
            if (!((raw[i] >= '0' && raw[i] <= '9') ||
                  (raw[i] >= 'a' && raw[i] <= 'f'))) return -1;
            if (raw[i] != '0') nonzero = 1;
        }
    }
    return nonzero ? 0 : -1;
}
int rnr_stage0_decode_installation(const unsigned char *raw, size_t bytes,
                                  struct rnr_stage0_installation *out)
{
    struct rnr_stage0_installation value = {0};
    if (out == NULL) return -1;
    /* Reject overlap before clearing can destroy any bytes to be decoded. */
    int alias = raw != NULL && overlap(raw,bytes,out,sizeof(*out));
    memset(out,0,sizeof(*out));
    if (raw == NULL || alias || (bytes != 128 && bytes != 448)) return -1;
    if (bytes == 128) {
        if (!header(raw,"RNRI0001")) return -1;
        value.version = 1;
    } else {
        if (memcmp(raw,"RNRI0002",8) != 0 || little(raw+8,4) != 2 ||
            little(raw+12,4) != 0 || !all_zero(raw+236,4) || !all_zero(raw+400,48) ||
            all_zero(raw+128,32) || all_zero(raw+160,16) || little(raw+184,8) == 0 ||
            boot_uuid(raw+200) != 0 || all_zero(raw+240,32) || all_zero(raw+272,32) ||
            all_zero(raw+304,32) || all_zero(raw+336,32) || all_zero(raw+368,32))
            return -1;
        value.version = 2;
        memcpy(value.project_id,raw+128,32);
        memcpy(value.store_instance,raw+160,16);
        value.store_device = little(raw+176,8);
        value.store_inode = little(raw+184,8);
        /* Explicit bit patterns; never cast host fsid_t or sign extend. */
        value.filesystem_id[0] = (uint32_t)little(raw+192,4);
        value.filesystem_id[1] = (uint32_t)little(raw+196,4);
        memcpy(value.boot_id,raw+200,36);
        memcpy(value.configuration_digest,raw+240,32);
        memcpy(value.enrollment_digest,raw+272,32);
        memcpy(value.startup_digest,raw+304,32);
        memcpy(value.execution_root,raw+336,32);
        memcpy(value.unit_policy_digest,raw+368,32);
    }
    if (all_zero(raw+96,32) ||
        image(raw+16,raw+48,little(raw+80,8),little(raw+88,8),131072,&value.runtime)!=0)
        return -1;
    memcpy(value.asset_root,raw+96,32);
    *out = value;
    return 0;
}
int rnr_stage0_decode_task(const unsigned char *raw, size_t bytes, struct rnr_stage0_task *out)
{
    struct rnr_stage0_task value = {0};
    if (out == NULL) return -1;
    int alias = raw != NULL && overlap(raw,bytes,out,sizeof(*out));
    memset(out,0,sizeof(*out));
    if (raw == NULL || bytes < 65 || bytes > 65600 || alias ||
        !header(raw,"RNRT0001") || all_zero(raw+16,16) || !all_zero(raw+44,20))
        return -1;
    uint64_t cutoff = little(raw+32,8), count = little(raw+40,4);
    if (cutoff == 0 || cutoff > INT64_MAX || count == 0 || count > 65536 ||
        count != bytes-64) return -1;
    memcpy(value.task_id,raw+16,16);
    value.wall_cutoff_ns = (int64_t)cutoff;
    value.payload = raw+64; value.payload_bytes = (size_t)count;
    *out = value;
    return 0;
}
int rnr_stage0_decode_output(const unsigned char *raw, size_t bytes, struct rnr_stage0_output *out)
{
    struct rnr_stage0_output value = {0};
    if (out == NULL) return -1;
    int alias = raw != NULL && overlap(raw,bytes,out,sizeof(*out));
    memset(out,0,sizeof(*out));
    if (raw == NULL || bytes != 128 || alias || !header(raw,"RNRP0001") ||
        all_zero(raw+16,16) || !all_zero(raw+112,16) ||
        image(raw+32,raw+64,little(raw+96,8),little(raw+104,8),1024,&value.launch)!=0)
        return -1;
    memcpy(value.task_id,raw+16,16);
    *out = value;
    return 0;
}

/* Closed canonical ASCII/integer v3 DATA parser, never an admission owner. */
enum json_kind { JSON_STRING=1, JSON_INTEGER, JSON_OBJECT, JSON_ARRAY };
struct json_token {
    uint64_t integer;
    uint32_t start, length;
    uint16_t end, children;
    unsigned char kind;
};
struct json_parser {
    const unsigned char *raw;
    size_t bytes, position;
    unsigned int used;
    struct json_token tokens[2048];
};
_Static_assert(sizeof(struct json_parser) <= 65536, "bounded parser storage");
static int json_take(struct json_parser *p, unsigned char c)
{
    if (p->position >= p->bytes || p->raw[p->position] != c) return -1;
    ++p->position; return 0;
}
static int json_slot(struct json_parser *p)
{
    if (p->used >= 2048) return -1;
    int index = (int)p->used++;
    p->tokens[index] = (struct json_token){0}; return index;
}
static int json_string(struct json_parser *p)
{
    if (json_take(p,'"') != 0) return -1;
    int index = json_slot(p); if (index < 0) return -1;
    struct json_token *t = &p->tokens[index];
    t->kind = JSON_STRING; t->start = (uint32_t)p->position;
    while (p->position < p->bytes && p->raw[p->position] != '"') {
        unsigned char c = p->raw[p->position];
        if (c < 32 || c > 126 || c == '\\' || p->position-t->start >= 4096) return -1;
        ++p->position;
    }
    t->length = (uint32_t)(p->position-t->start);
    if (json_take(p,'"') != 0) return -1;
    t->end = (uint16_t)p->used; return index;
}
static int json_key_order(const struct json_parser *p, int first, int second)
{
    const struct json_token *a=&p->tokens[first], *b=&p->tokens[second];
    size_t length=a->length < b->length ? a->length : b->length;
    int result=memcmp(p->raw+a->start,p->raw+b->start,length);
    return result < 0 || (result == 0 && a->length < b->length);
}
static int json_value(struct json_parser *p, unsigned int depth)
{
    if (p->position >= p->bytes) return -1;
    unsigned char first=p->raw[p->position];
    if (first=='"') return json_string(p);
    int index=json_slot(p); if(index<0)return -1;
    struct json_token *t=&p->tokens[index]; t->start=(uint32_t)p->position;
    if (first=='{' || first=='[') {
        if(depth>=12)return -1;
        int object=first=='{', previous=-1;
        unsigned char end=object?'}':']';
        t->kind=object?JSON_OBJECT:JSON_ARRAY; ++p->position;
        if (p->position < p->bytes && p->raw[p->position]==end) ++p->position;
        else for (;;) {
            if(object){
                int key=json_string(p);
                if(key<0 || (previous>=0 && !json_key_order(p,previous,key)) || json_take(p,':')!=0)return -1;
                previous=key;
            }
            if(json_value(p,depth+1)<0)return -1;
            ++t->children;
            if(p->position < p->bytes && p->raw[p->position]==end){++p->position;break;}
            if(json_take(p,',')!=0)return -1;
        }
    } else {
        if(first<'0'||first>'9')return -1;
        t->kind=JSON_INTEGER;
        do {
            unsigned int digit=(unsigned int)(p->raw[p->position]-'0');
            if(t->integer>((uint64_t)INT64_MAX-digit)/10)return -1;
            t->integer=t->integer*10+digit; ++p->position;
            if(first=='0')break;
        } while(p->position<p->bytes && p->raw[p->position]>='0' && p->raw[p->position]<='9');
    }
    t->length=(uint32_t)(p->position-t->start); t->end=(uint16_t)p->used; return index;
}
static int json_equal(const struct json_parser *p, int index, const char *text)
{
    const struct json_token *t=&p->tokens[index]; size_t length=strlen(text);
    return t->kind==JSON_STRING && t->length==length && memcmp(p->raw+t->start,text,length)==0;
}
static int json_schema(const struct json_parser *p, int index,
                         const char *const *keys, unsigned int count, int *values)
{
    const struct json_token *t=&p->tokens[index];
    if(t->kind!=JSON_OBJECT || t->children!=count)return -1;
    unsigned int next=(unsigned int)index+1;
    for(unsigned int i=0;i<count;++i){
        if(next+1>=t->end || !json_equal(p,(int)next,keys[i]))return -1;
        values[i]=(int)next+1; next=p->tokens[next+1].end;
    }
    return next==t->end?0:-1;
}
static int json_number(const struct json_parser *p, int index, uint64_t minimum,
                         uint64_t maximum, uint64_t *out)
{
    const struct json_token *t=&p->tokens[index];
    if(t->kind!=JSON_INTEGER || t->integer<minimum || t->integer>maximum)return -1;
    *out=t->integer; return 0;
}
static int json_text(const struct json_parser *p, int index, size_t minimum,
                       size_t maximum, struct rnr_stage0_text_view *out)
{
    const struct json_token *t=&p->tokens[index];
    if(t->kind!=JSON_STRING || t->length<minimum || t->length>maximum)return -1;
    *out=(struct rnr_stage0_text_view){p->raw+t->start,t->length}; return 0;
}
static int json_hex(const struct json_parser *p, int index, size_t bytes, unsigned char *out)
{
    const struct json_token *t=&p->tokens[index];
    if(t->kind!=JSON_STRING || t->length!=bytes*2)return -1;
    for(size_t i=0;i<bytes*2;++i){
        unsigned char c=p->raw[t->start+i]; unsigned int n;
        if(c>='0'&&c<='9')n=(unsigned int)(c-'0');
        else if(c>='a'&&c<='f')n=(unsigned int)(c-'a')+10;
        else return -1;
        if(!(i%2))out[i/2]=(unsigned char)(n<<4);else out[i/2]|=(unsigned char)n;
    }
    return 0;
}
static int json_store(const struct json_parser *p, int index,
                        struct rnr_stage0_launch_declaration *out)
{
    static const char *const keys[]={"policy","queue_bound","resources","run","run_id","supervisor_epoch"};
    static const char *const policy[]={"effort","input_bytes","item_text_bytes","model","turn_items"};
    static const char *const resources[]={"reviewer_reserve","runtime_slots","workload_slots"};
    static const char *const run[]={"capacity","commands","deadline","turn_capacity","turns"};
    int v[6],a[5];uint64_t seconds;
    if(json_schema(p,index,keys,6,v)!=0 || json_schema(p,v[0],policy,5,a)!=0 ||
        json_text(p,a[0],1,256,&out->effort)!=0 || json_text(p,a[3],1,256,&out->model)!=0 ||
        json_number(p,a[1],1,1000000,&out->input_bytes)!=0 ||
        json_number(p,a[2],1,1000000,&out->item_text_bytes)!=0 ||
        json_number(p,a[4],1,1000000,&out->turn_items)!=0 ||
        json_number(p,v[1],1,1000000,&out->queue_bound)!=0 ||
        json_text(p,v[4],1,256,&out->run_id)!=0 || json_text(p,v[5],1,256,&out->supervisor_epoch)!=0 ||
        json_schema(p,v[2],resources,3,a)!=0 ||
        json_number(p,a[0],0,INT64_MAX,&out->reviewer_reserve)!=0 ||
        json_number(p,a[1],1,1000000,&out->runtime_slots)!=0 ||
        json_number(p,a[2],1,1000000,&out->workload_slots)!=0 ||
        out->reviewer_reserve>=out->runtime_slots || json_schema(p,v[3],run,5,a)!=0 ||
        json_number(p,a[0],1,1000000,&out->run_capacity)!=0 ||
        json_number(p,a[1],1,1000000,&out->run_commands)!=0 ||
        json_number(p,a[2],1,INT64_MAX/1000000000,&seconds)!=0 ||
        json_number(p,a[3],1,1000000,&out->run_turn_capacity)!=0 ||
        json_number(p,a[4],1,1000000,&out->run_turns)!=0 ||
        out->run_capacity!=out->workload_slots)return -1;
    out->positive_wall_ns=(int64_t)seconds*1000000000;return 0;
}
static int json_quota(const struct json_parser *p, int index,
                        struct rnr_stage0_launch_declaration *out)
{
    static const char *const keys[]={"cpu_millis","memory_bytes","output_bytes","pids","scratch_bytes","swap_bytes"};
    uint64_t *const fields[]={&out->cpu_millis,&out->memory_bytes,&out->output_bytes,&out->pids,&out->scratch_bytes,&out->swap_bytes};
    int v[6];if(json_schema(p,index,keys,6,v)!=0)return -1;
    for(unsigned int i=0;i<6;++i)
        if(json_number(p,v[i],i==5?0:1,i==5?0:(uint64_t)INT64_MAX,fields[i])!=0)return -1;
    if(out->cpu_millis%10 || out->cpu_millis>(uint64_t)INT64_MAX/1000000)return -1;
    return 0;
}
static int json_files(const struct json_parser *p, int index,
                        struct rnr_stage0_launch_declaration *out)
{
    static const char *const keys[]={"bytes","content_digest","target"};
    static const char *const targets[]={"/etc/codex/config.toml","/etc/codex/managed_config.toml",
        "/etc/codex/requirements.toml","/rnr/catalog.json","/rnr/codex","/rnr/guardian","/rnr/home/config.toml"};
    const struct json_token *t=&p->tokens[index];unsigned int next=(unsigned int)index+1;
    if(t->kind!=JSON_ARRAY || t->children!=7)return -1;
    for(unsigned int i=0;i<7;++i){
        int v[3];int executable=i==4||i==5;
        if(json_schema(p,(int)next,keys,3,v)!=0 || !json_equal(p,v[2],targets[i]) ||
            json_hex(p,v[1],32,out->files[i].digest)!=0 ||
            json_number(p,v[0],executable?1:0,executable?1073741824:2097152,&out->files[i].bytes)!=0)return -1;
        next=p->tokens[next].end;
    }
    return next==t->end?0:-1;
}
static int unit_path(const struct rnr_stage0_text_view *v)
{
    if(v->length<2 || v->bytes[0]!='/')return -1;
    unsigned int components=1;size_t start=1;
    for(size_t i=1;i<=v->length;++i){
        if(i==v->length || v->bytes[i]=='/'){
            size_t length=i-start;
            if(++components>16 || length==0 || (length==1&&v->bytes[start]=='.') ||
                (length==2&&v->bytes[start]=='.'&&v->bytes[start+1]=='.'))return -1;
            start=i+1;
        }else{
            unsigned char c=v->bytes[i];
            if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='.'||c=='-'))return -1;
        }
    }
    return 0;
}
static int json_paths(const struct json_parser *p, int index,
                        struct rnr_stage0_launch_declaration *out)
{
    const struct json_token *t=&p->tokens[index];unsigned int next=(unsigned int)index+1;int transient=0;
    if(t->kind!=JSON_ARRAY || t->children<1 || t->children>32)return -1;
    for(unsigned int i=0;i<t->children;++i){
        struct rnr_stage0_text_view *v=&out->unit_paths[i];
        if(json_text(p,(int)next,1,256,v)!=0 || unit_path(v)!=0)return -1;
        for(unsigned int j=0;j<i;++j)
            if(v->length==out->unit_paths[j].length && memcmp(v->bytes,out->unit_paths[j].bytes,v->length)==0)return -1;
        if(json_equal(p,(int)next,"/run/systemd/transient"))transient=1;
        next=p->tokens[next].end;
    }
    out->unit_path_count=t->children;return next==t->end&&transient?0:-1;
}
int rnr_stage0_decode_launch_declaration(const unsigned char *raw, size_t bytes,
                                        struct rnr_stage0_launch_declaration *out)
{
    if(out==NULL)return -1;
    int alias=raw!=NULL && overlap(raw,bytes,out,sizeof(*out));
    memset(out,0,sizeof(*out));
    if(raw==NULL || alias || bytes==0 || bytes>65536)return -1;
    struct json_parser p={.raw=raw,.bytes=bytes};
    struct rnr_stage0_launch_declaration value={0};
    static const char *const keys[]={"allocation","asset_root","daemon_digest","execution_root","files",
        "manager_digest","quota","store","tool_digest","unit_paths","version"};
    int v[11];uint64_t version;
    if(json_value(&p,0)!=0 || p.position!=bytes || json_schema(&p,0,keys,11,v)!=0 ||
        json_hex(&p,v[0],16,value.allocation)!=0 || json_hex(&p,v[1],32,value.asset_root)!=0 ||
        json_hex(&p,v[2],32,value.daemon_digest)!=0 || json_hex(&p,v[3],32,value.execution_root)!=0 ||
        json_files(&p,v[4],&value)!=0 || json_hex(&p,v[5],32,value.manager_digest)!=0 ||
        json_quota(&p,v[6],&value)!=0 || json_store(&p,v[7],&value)!=0 ||
        json_hex(&p,v[8],32,value.tool_digest)!=0 || json_paths(&p,v[9],&value)!=0 ||
        json_number(&p,v[10],3,3,&version)!=0)return -1;
    value.version=(uint32_t)version;*out=value;return 0;
}

static int policy_text(const unsigned char *raw,size_t capacity,uint32_t count,
                       struct rnr_stage0_text_view *out)
{
    if(count<1 || count>capacity || !all_zero(raw+count,capacity-count))return -1;
    for(size_t j=0;j<count;++j)if(raw[j]<1 || raw[j]>127)return -1;
    out->bytes=raw;out->length=count;return 0;
}
static int policy_repository(const struct rnr_stage0_text_view *v)
{
    size_t split=v->length;
    for(size_t j=0;j<v->length;++j){
        unsigned char c=v->bytes[j];
        if(c=='/'){
            if(split!=v->length)return -1;
            split=j;
        }else if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
                   (c>='0'&&c<='9')||c=='_'||c=='.'||c=='-'))return -1;
    }
    if(split==0 || split>=v->length-1)return -1;
    size_t lengths[]={split,v->length-split-1};
    const unsigned char *parts[]={v->bytes,v->bytes+split+1};
    for(size_t i=0;i<2;++i)
        if((lengths[i]==1&&parts[i][0]=='.') ||
           (lengths[i]==2&&parts[i][0]=='.'&&parts[i][1]=='.'))return -1;
    return 0;
}
static int policy_host(const struct rnr_stage0_text_view *v)
{
    for(size_t j=0;j<v->length;++j){
        unsigned char c=v->bytes[j];
        if(c!=' ' && !(c>=9&&c<=13))return 0;
    }
    return -1;
}
int rnr_stage0_decode_policy(const unsigned char *raw,size_t bytes,
                            struct rnr_stage0_policy *out)
{
    struct rnr_stage0_policy v={0};
    if(out==NULL)return -1;
    int alias=raw!=NULL&&overlap(raw,bytes,out,sizeof(*out));
    memset(out,0,sizeof(*out));
    if(raw==NULL || alias || bytes!=9728 || memcmp(raw,"RNRPOL01",8) ||
       little(raw+8,4)!=1 || little(raw+12,4)!=9728 ||
       all_zero(raw+16,32) || all_zero(raw+48,16) || boot_uuid(raw+64)!=0 ||
       little(raw+100,4)!=1 || !all_zero(raw+1020,4))return -1;
    v.version=1;v.flags=1;
    memcpy(v.project_id,raw+16,32);memcpy(v.store_instance,raw+48,16);memcpy(v.boot_id,raw+64,36);
    unsigned char *digests[]={v.configuration_digest,v.enrollment_digest,v.startup_digest,
        v.native_digest,v.manager_digest,v.python_digest,v.execution_root,v.asset_root,
        v.tool_digest,v.daemon_digest};
    for(size_t i=0;i<10;++i){
        if(all_zero(raw+104+32*i,32))return -1;
        memcpy(digests[i],raw+104+32*i,32);
    }
    v.revision_bytes=(size_t)little(raw+424,4);
    if((v.revision_bytes!=20 && v.revision_bytes!=32) ||
       all_zero(raw+428,v.revision_bytes) ||
       !all_zero(raw+428+v.revision_bytes,32-v.revision_bytes))return -1;
    memcpy(v.revision,raw+428,v.revision_bytes);
    if(policy_text(raw+464,256,(uint32_t)little(raw+460,4),&v.repository)!=0 ||
       policy_repository(&v.repository)!=0 ||
       policy_text(raw+724,256,(uint32_t)little(raw+720,4),&v.host)!=0 ||
       policy_host(&v.host)!=0)return -1;
    uint64_t *elf_sizes[]={&v.native_bytes,&v.manager_bytes,&v.python_bytes};
    for(size_t i=0;i<3;++i){
        uint64_t n=little(raw+980+8*i,8);
        if(n<1 || n>33554432)return -1;
        *elf_sizes[i]=n;
    }
    uint32_t *file_sizes[]={&v.configuration_bytes,&v.enrollment_bytes,&v.startup_bytes};
    for(size_t i=0;i<3;++i){
        uint64_t n=little(raw+1004+4*i,4);
        if(n<1 || n>(i==2?1048576:131072))return -1;
        *file_sizes[i]=(uint32_t)n;
    }
    for(size_t i=0;i<4;++i){
        const unsigned char *p=raw+1024+128*i;
        struct rnr_stage0_policy_unit *u=&v.units[i];
        if(all_zero(p,32) || !all_zero(p+72,56))return -1;
        memcpy(u->fragment_digest,p,32);
        u->cpu_millis=little(p+32,8);u->memory_bytes=little(p+40,8);
        u->swap_bytes=little(p+48,8);u->pids=little(p+56,8);u->cpu_period_us=little(p+64,8);
        if(u->cpu_millis<1 || u->cpu_millis%10 || u->cpu_millis>(uint64_t)INT64_MAX/1000 ||
           u->memory_bytes<1 || u->memory_bytes>INT64_MAX ||
           u->pids<1 || u->pids>INT64_MAX || u->swap_bytes!=0 || u->cpu_period_us!=100000)return -1;
    }
    const struct rnr_stage0_policy_unit *service=&v.units[0],*control=&v.units[1],
        *workload=&v.units[2],*anchor=&v.units[3];
    if(service->cpu_millis>control->cpu_millis || service->memory_bytes>control->memory_bytes ||
       service->pids>control->pids || anchor->cpu_millis!=workload->cpu_millis ||
       anchor->memory_bytes!=workload->memory_bytes || anchor->pids!=workload->pids)return -1;
    v.unit_path_count=(size_t)little(raw+1016,4);
    if(v.unit_path_count<1 || v.unit_path_count>32)return -1;
    int transient=0;
    for(size_t i=0;i<32;++i){
        const unsigned char *p=raw+1536+256*i;
        if(i>=v.unit_path_count){if(!all_zero(p,256))return -1;continue;}
        struct rnr_stage0_text_view *path=&v.unit_paths[i];
        if(!all_zero(p+4,4) || policy_text(p+8,248,(uint32_t)little(p,4),path)!=0 ||
           unit_path(path)!=0)return -1;
        for(size_t j=0;j<i;++j)
            if(path->length==v.unit_paths[j].length &&
               memcmp(path->bytes,v.unit_paths[j].bytes,path->length)==0)return -1;
        if(path->length==22 && !memcmp(path->bytes,"/run/systemd/transient",22))transient=1;
    }
    if(!transient)return -1;
    *out=v;return 0;
}
