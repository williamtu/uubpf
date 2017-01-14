#include <openvswitch/hmap.h>
#include <string.h>
#include <stdint.h>
#include <error.h>
#include <stdio.h>
#include "bpf.h"
#include "hmap.h"

static uint32_t cur_hmap_index;
struct uhmap_elem {
    struct hmap hmap;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t map_type;
    uint32_t map_flags;
    uint32_t max_entries;
};
struct uhmap_elem ubpf_hmap_array[1024];

struct elem {
    struct hmap_node node;
    void *key;
    int key_size;
    void *value;
    int value_size;
};

static inline uint32_t hash_rot(uint32_t x, int k)
{
    return (x << k) | (x >> (32 - k));
}

//static inline uint32_t mhash_add__(uint32_t hash, uint32_t data)
static inline uint32_t hash_add(uint32_t hash, uint32_t data)
{
    /* zero-valued 'data' will not change the 'hash' value */
    if (!data) {
        return hash;
    }

    data *= 0xcc9e2d51;
    data = hash_rot(data, 15);
    data *= 0x1b873593;
    return hash ^ data;
}

struct uhmap_elem *ubpf_get_hmap(int id)
{
    return &ubpf_hmap_array[id];
}

struct uhmap_elem *ubpf_alloc_hmap(int id)
{
    return &ubpf_hmap_array[id];
}

int get_next_hmap(void)
{
    return cur_hmap_index++ % 1024;
}

int ubpf_insert_map(union bpf_attr *attr)
{
    int i;
    struct uhmap_elem *hmap;
    struct elem *elem;
    uint32_t hash = 0;
    void *key, *value;
    int id = attr->map_fd;
    
    printf("%s map_id %d\n", __func__, id);

    /* lookup existing map */
    hmap = ubpf_get_hmap(id);

    key = (void *) attr->key;
    value = (void *) attr->value;

    elem = malloc(sizeof(struct elem));
    if (!elem)
        return -1;

    elem->key_size = hmap->key_size;
    elem->key = malloc(hmap->key_size);
    memcpy(elem->key, key, hmap->key_size);

    elem->value_size = hmap->value_size;
    elem->value = malloc(hmap->value_size);
    memcpy(elem->value, value, hmap->value_size);

    for (i = 0; i < hmap->key_size / 4; i++) {
        hash = hash_add(hash, *(uint32_t *)key);
        key += 4;
    }

    printf("%s hash %x\n", __func__, hash);
    hmap_insert(&hmap->hmap, &elem->node, hash);

    return 0;
}

void *ubpf_lookup_map(union bpf_attr *attr)
{
    int i;
    struct uhmap_elem *hmap;
    struct elem *elem;
    struct hmap_node *node;
    uint32_t hash = 0;
    void *key, *value;
    int id = attr->map_fd;

    key = (void *) attr->key;
    value = (void *) attr->value;

    hmap = ubpf_get_hmap(id);

    for (i = 0; i < hmap->key_size / 4; i++) {
        hash = hash_add(hash, *(uint32_t *)key);
        key += 4;
    }

    printf("%s hash = %x\n", __func__, hash);

    node = hmap_first_with_hash(&hmap->hmap, hash);
    if (!node)
        return NULL;

    elem = CONTAINER_OF(node, struct elem, node);

    memcpy(value, elem->value, hmap->value_size);

    return value;
}

/* return a pseudo file descriptor */
int ubpf_create_map(union bpf_attr *attr)
{
    struct uhmap_elem *hmap;
    uint32_t id;

	printf("enter %s\n", __func__);
    id = get_next_hmap();
    hmap = ubpf_alloc_hmap(id);
    hmap_init(&hmap->hmap);
    hmap->key_size = attr->key_size;
    hmap->value_size = attr->value_size;
    hmap->map_flags = attr->map_flags;
    hmap->max_entries = attr->max_entries;

	return id;
}

#if 0
int main()
{
    struct hmap hmap;
	union bpf_attr cattr, lattr, iattr;
	uint32_t key = 0xdeadbeef;
	uint64_t value = 0xdeaddeadbeefbeef;
	int id;

    cur_hmap_index = 0;

	// create a map	
	cattr.key_size = 4;
	cattr.value_size = 8;
	id = ubpf_create_map(&cattr);

	//insert a map
	iattr.key = (uint64_t) &key; 
	iattr.value = (uint64_t) &value;
	iattr.map_fd = id;
	ubpf_insert_map(&iattr);

	//lookup a map
	lattr.key = (uint64_t) &key; 
	lattr.value = (uint64_t) &value;
	lattr.map_fd = id;
	ubpf_lookup_map(&lattr);

    return 0;
}
#endif
