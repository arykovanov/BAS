#include "opcua_packed.h"
#include "opcua_ns0.h"

#include <lauxlib.h>
#include <limits.h>
#include <string.h>

#define PROVIDER_MT "opcua.packed.provider"
#define NODE_MT "opcua.packed.node"
#define ATTRS_MT "opcua.packed.attrs"
#define REFS_MT "opcua.packed.refs"

#define VALUE_FALSE 1u
#define VALUE_TRUE 2u
#define VALUE_INTEGER 3u
#define VALUE_NUMBER 4u
#define VALUE_STRING 5u
#define VALUE_TABLE 6u
#define MAX_VALUE_DEPTH 64u

typedef struct PackedProvider
{
   /* First byte of the complete packed blob. */
   const uint8_t* data;

   /* Total blob size in bytes, including the header. */
   size_t size;

   /* Number of nodes indexed by the two parallel offset arrays. */
   uint32_t nodeCount;

   /* Absolute byte offset of the sorted NodeId-offset array. */
   uint32_t nodeIdIndexOffset;

   /* Absolute byte offset of the node-body-offset array. */
   uint32_t nodeBodyIndexOffset;

   /* Absolute byte offset of the variable-size node bodies. */
   uint32_t nodeBodyOffset;

   /* Total bytes occupied by all variable-size node bodies. */
   uint32_t nodeBodySize;

   /* Total attribute records for all nodes. */
   uint32_t attributeCount;

   /* Total reference records owned by blob nodes. */
   uint32_t referenceCount;

   /* Number of inverse references whose target is outside this blob. */
   uint32_t externalReferenceCount;

   /* Absolute byte offset of the external-reference index. */
   uint32_t externalReferenceOffset;

   /* Total non-attribute metadata records for all nodes. */
   uint32_t fieldCount;

   /* Absolute byte offset of encoded attribute and metadata values. */
   uint32_t valueOffset;

   /* Size in bytes of the encoded-value section. */
   uint32_t valueSize;

   /* Absolute byte offset of the length-prefixed string pool. */
   uint32_t stringOffset;

   /* Size in bytes of the string pool. */
   uint32_t stringSize;

   /* Width in bytes of node indices stored in external references. */
   uint8_t indexWidth;

   /* Width of NodeId string offsets in the sorted node index. */
   uint8_t nodeIdOffsetWidth;

   /* Width of offsets relative to the node-body section. */
   uint8_t nodeBodyOffsetWidth;

   /* Width in bytes of relative string-pool offsets. */
   uint8_t stringOffsetWidth;

   /* Width in bytes of relative encoded-value offsets. */
   uint8_t valueOffsetWidth;

   /* Width in bytes of each string-pool entry's length prefix. */
   uint8_t stringLengthWidth;

   /* Size of one AttributeRecord for the selected value-offset width. */
   uint8_t attributeRecordSize;

   /* Size of one source-node/local-reference external index record. */
   uint8_t externalReferenceRecordSize;

   /* Size of one ReferenceRecord for the selected string-offset width. */
   uint8_t referenceRecordSize;

   /* Size of one FieldRecord for the selected string-offset width. */
   uint8_t fieldRecordSize;
} PackedProvider;

typedef struct PackedView
{
   /* Provider that owns the blob and the indexed node. */
   PackedProvider* provider;

   /* Offset of the node body relative to the node-body section. */
   uint32_t nodeOffset;
} PackedView;

typedef enum PackedChecksumPolicy
{
   /* Trust a blob compiled into the same firmware image. */
   PACKED_CHECKSUM_SKIP,

   /* Verify a blob supplied dynamically by Lua. */
   PACKED_CHECKSUM_VERIFY
} PackedChecksumPolicy;

/* Read an unaligned little-endian 16-bit integer from the blob. */
static uint16_t readU16(const uint8_t* p)
{
   return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* Read an unaligned little-endian 32-bit integer from the blob. */
static uint32_t readU32(const uint8_t* p)
{
   return (uint32_t)p[0] |
      ((uint32_t)p[1] << 8) |
      ((uint32_t)p[2] << 16) |
      ((uint32_t)p[3] << 24);
}

/* Read a record index using the width selected by the blob header. */
static uint32_t readIndex(const uint8_t* p, uint8_t width)
{
   if (width == 1u)
      return p[0];
   if (width == 2u)
      return readU16(p);
   return readU32(p);
}

/* Read a relative string-pool offset using the width in the blob header. */
static uint32_t readStringOffset(
   const PackedProvider* provider, const uint8_t* p)
{
   return readIndex(p, provider->stringOffsetWidth);
}

/* Read an offset relative to the beginning of the encoded-value section. */
static uint32_t readValueOffset(
   const PackedProvider* provider, const uint8_t* p)
{
   return readIndex(p, provider->valueOffsetWidth);
}

/* Read an unaligned little-endian 64-bit integer from the blob. */
static uint64_t readU64(const uint8_t* p)
{
   uint64_t value = 0;
   unsigned i;
   for (i = 0; i < 8; ++i)
      value |= (uint64_t)p[i] << (i * 8);
   return value;
}

/* Calculate the blob CRC while treating the checksum field as zero. */
static uint32_t crc32Blob(const uint8_t* data, size_t size)
{
   uint32_t crc = 0xFFFFFFFFu;
   size_t i;
   for (i = 0; i < size; ++i)
   {
      uint8_t value = (i >= 12u && i < 16u) ? 0u : data[i];
      unsigned bit;
      crc ^= value;
      for (bit = 0; bit < 8; ++bit)
      {
         uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
         crc = (crc >> 1) ^ (0xEDB88320u & mask);
      }
   }
   return ~crc;
}

/* Verify that a fixed-record section ends at the expected next section. */
static int checkedSection(
   uint32_t offset,
   uint32_t count,
   uint32_t recordSize,
   uint32_t expectedEnd)
{
   uint64_t end = (uint64_t)offset + (uint64_t)count * recordSize;
   return end == expectedEnd;
}

/* Resolve a length-prefixed string-pool entry and validate its bounds. */
static int getString(
   const PackedProvider* provider,
   uint32_t relativeOffset,
   const uint8_t** value,
   uint32_t* length)
{
   uint64_t entry = (uint64_t)provider->stringOffset + relativeOffset;
   uint32_t size;
   if (relativeOffset > provider->stringSize ||
       entry + provider->stringLengthWidth > provider->size)
      return 0;

   size = readIndex(
      provider->data + (size_t)entry, provider->stringLengthWidth);
   if ((uint64_t)relativeOffset + provider->stringLengthWidth + size >
       provider->stringSize)
      return 0;

   *value = provider->data + (size_t)entry + provider->stringLengthWidth;
   *length = size;
   return 1;
}

/* Validate every variable-length string-pool entry and the selected width. */
static int validateStringPool(
   const PackedProvider* provider, const char** error)
{
   uint32_t offset = 0;
   uint32_t maxLength = 0;
   uint8_t expectedWidth;
   while (offset < provider->stringSize)
   {
      uint32_t remaining = provider->stringSize - offset;
      uint32_t length;
      if (remaining < provider->stringLengthWidth)
      {
         *error = "packed string length prefix is truncated";
         return 0;
      }
      length = readIndex(
         provider->data + provider->stringOffset + offset,
         provider->stringLengthWidth);
      if (length > remaining - provider->stringLengthWidth)
      {
         *error = "packed string data is truncated";
         return 0;
      }
      if (length > maxLength)
         maxLength = length;
      offset += provider->stringLengthWidth + length;
   }
   expectedWidth = maxLength <= 0xFFu ? 1u :
      (maxLength <= 0xFFFFu ? 2u : 4u);
   if (provider->stringLengthWidth != expectedWidth)
   {
      *error = "packed string length width is not minimal";
      return 0;
   }
   return 1;
}

/*
 * Validate and skip one recursively encoded value without allocating Lua data.
 */
static int skipValue(
   const PackedProvider* provider,
   const uint8_t** cursor,
   unsigned depth)
{
   const uint8_t* p = *cursor;
   const uint8_t* end =
      provider->data + provider->valueOffset + provider->valueSize;
   uint8_t tag;

   if (depth > MAX_VALUE_DEPTH || p >= end)
      return 0;
   tag = *p++;

   switch (tag)
   {
      case VALUE_FALSE:
      case VALUE_TRUE:
         break;

      case VALUE_INTEGER:
      case VALUE_NUMBER:
         if ((size_t)(end - p) < 8u)
            return 0;
         p += 8;
         break;

      case VALUE_STRING:
      {
         const uint8_t* value;
         uint32_t length;
         if ((size_t)(end - p) < provider->stringOffsetWidth ||
             !getString(
                provider, readStringOffset(provider, p), &value, &length))
            return 0;
         p += provider->stringOffsetWidth;
         break;
      }

      case VALUE_TABLE:
      {
         uint32_t count;
         uint32_t i;
         if ((size_t)(end - p) < 4u)
            return 0;
         count = readU32(p);
         p += 4;
         for (i = 0; i < count; ++i)
         {
            if (!skipValue(provider, &p, depth + 1) ||
                !skipValue(provider, &p, depth + 1))
               return 0;
         }
         break;
      }

      default:
         return 0;
   }

   *cursor = p;
   return 1;
}

/* Return a NodeId string offset from the sorted node index. */
static uint32_t nodeIdOffset(
   const PackedProvider* provider,
   uint32_t index)
{
   return readIndex(
      provider->data + provider->nodeIdIndexOffset +
         (size_t)index * provider->nodeIdOffsetWidth,
      provider->nodeIdOffsetWidth);
}

/* Return a node-body offset from its parallel index. */
static uint32_t indexedNodeBodyOffset(
   const PackedProvider* provider,
   uint32_t index)
{
   return readIndex(
      provider->data + provider->nodeBodyIndexOffset +
         (size_t)index * provider->nodeBodyOffsetWidth,
      provider->nodeBodyOffsetWidth);
}

/* Return a node body by its offset relative to the node-body section. */
static const uint8_t* nodeBody(
   const PackedProvider* provider,
   uint32_t offset)
{
   return provider->data + provider->nodeBodyOffset + offset;
}

/* Return the node body selected by a zero-based node index. */
static const uint8_t* indexedNodeBody(
   const PackedProvider* provider,
   uint32_t index)
{
   return nodeBody(provider, indexedNodeBodyOffset(provider, index));
}

/* Return the number of attributes owned by a node. */
static uint8_t nodeAttributeCount(const uint8_t* node)
{
   return (uint8_t)(node[0] & 0x7Fu);
}

/* Return the number of metadata fields owned by a node. */
static uint8_t nodeFieldCount(const uint8_t* node)
{
   return (node[0] & 0x80u) != 0u ? node[1] : 0u;
}

/* Return the byte size of a node body's count header. */
static uint8_t nodeHeaderSize(const uint8_t* node)
{
   return (uint8_t)(((node[0] & 0x80u) != 0u) ? 4u : 3u);
}

/* Return the number of references owned by a node. */
static uint16_t nodeReferenceCount(const uint8_t* node)
{
   return readU16(node + (((node[0] & 0x80u) != 0u) ? 2u : 1u));
}

/* Return the first inline attribute record owned by a node. */
static const uint8_t* nodeAttributes(const uint8_t* node)
{
   return node + nodeHeaderSize(node);
}

/* Return the first inline reference record owned by a node. */
static const uint8_t* nodeReferences(
   const PackedProvider* provider,
   const uint8_t* node)
{
   return nodeAttributes(node) +
      (size_t)nodeAttributeCount(node) * provider->attributeRecordSize;
}

/* Return the first inline metadata-field record owned by a node. */
static const uint8_t* nodeFields(
   const PackedProvider* provider,
   const uint8_t* node)
{
   return nodeReferences(provider, node) +
      (size_t)nodeReferenceCount(node) * provider->referenceRecordSize;
}

/* Return the calculated byte size of one complete node body. */
static size_t nodeBodySize(
   const PackedProvider* provider,
   const uint8_t* node)
{
   return nodeHeaderSize(node) +
      (size_t)nodeAttributeCount(node) * provider->attributeRecordSize +
      (size_t)nodeReferenceCount(node) * provider->referenceRecordSize +
      (size_t)nodeFieldCount(node) * provider->fieldRecordSize;
}

/* Return an external-reference index entry by its zero-based index. */
static const uint8_t* externalReferenceRecord(
   const PackedProvider* provider,
   uint32_t index)
{
   return provider->data + provider->externalReferenceOffset +
      (size_t)index * provider->externalReferenceRecordSize;
}

/* Compare two arbitrary byte strings in deterministic lexical order. */
static int compareBytes(
   const uint8_t* a,
   size_t aLength,
   const uint8_t* b,
   size_t bLength)
{
   size_t length = aLength < bLength ? aLength : bLength;
   int result = memcmp(a, b, length);
   if (result != 0)
      return result;
   if (aLength < bLength)
      return -1;
   if (aLength > bLength)
      return 1;
   return 0;
}

static int findNode(
   const PackedProvider* provider,
   const char* nodeId,
   size_t nodeIdLength,
   uint32_t* result);
static int findField(
   const PackedView* view,
   const char* key,
   size_t keyLength,
   const uint8_t** result);
static int findTypeInfoNode(
   lua_State* L,
   const PackedView* view,
   uint32_t* result);

/*
 * Parse and validate a provider header and all referenced records.
 * Check the CRC for external blobs, but allow trusted firmware blobs to skip
 * the additional full-blob pass.
 */
static int validateProvider(
   PackedProvider* provider,
   PackedChecksumPolicy checksumPolicy,
   const char** error)
{
   const uint8_t* data = provider->data;
   uint32_t totalSize;
   uint32_t checksum;
   uint32_t i;
   uint64_t indexCapacity;
   uint64_t expectedNodeBodyOffset = 0;
   uint64_t nodeIdStringSize = 0;
   uint64_t validatedAttributeCount = 0;
   uint64_t validatedReferenceCount = 0;
   uint64_t validatedFieldCount = 0;

   if (provider->size < OPCUA_PACKED_HEADER_SIZE)
   {
      *error = "blob is shorter than the packed header";
      return 0;
   }
   if (memcmp(data, "UAPB", 4) != 0)
   {
      *error = "invalid packed magic";
      return 0;
   }
   if (readU16(data + 4) != OPCUA_PACKED_VERSION)
   {
      *error = "unsupported packed version";
      return 0;
   }
   if (readU16(data + 6) != OPCUA_PACKED_HEADER_SIZE)
   {
      *error = "invalid packed header size";
      return 0;
   }

   totalSize = readU32(data + 8);
   checksum = readU32(data + 12);
   if (totalSize != provider->size)
   {
      *error = "packed total size does not match the source";
      return 0;
   }
   if (checksumPolicy == PACKED_CHECKSUM_VERIFY &&
       crc32Blob(data, provider->size) != checksum)
   {
      *error = "packed CRC mismatch";
      return 0;
   }

   provider->nodeCount = readU32(data + 16);
   provider->nodeIdIndexOffset = readU32(data + 20);
   provider->nodeBodyIndexOffset = readU32(data + 24);
   provider->nodeBodyOffset = readU32(data + 28);
   provider->nodeBodySize = readU32(data + 32);
   provider->attributeCount = readU32(data + 36);
   provider->referenceCount = readU32(data + 40);
   provider->externalReferenceCount = readU32(data + 44);
   provider->externalReferenceOffset = readU32(data + 48);
   provider->fieldCount = readU32(data + 52);
   provider->valueOffset = readU32(data + 56);
   provider->valueSize = readU32(data + 60);
   provider->stringOffset = readU32(data + 64);
   provider->stringSize = readU32(data + 68);
   provider->indexWidth = data[72];
   provider->nodeIdOffsetWidth = data[73];
   provider->nodeBodyOffsetWidth = data[74];
   provider->stringOffsetWidth = data[75];
   provider->valueOffsetWidth = data[76];
   provider->stringLengthWidth = data[77];

   if ((provider->indexWidth != 1u && provider->indexWidth != 2u &&
        provider->indexWidth != 4u) ||
       (provider->nodeIdOffsetWidth != 1u &&
        provider->nodeIdOffsetWidth != 2u &&
        provider->nodeIdOffsetWidth != 4u) ||
       (provider->nodeBodyOffsetWidth != 1u &&
        provider->nodeBodyOffsetWidth != 2u &&
        provider->nodeBodyOffsetWidth != 4u) ||
       (provider->stringOffsetWidth != 1u &&
        provider->stringOffsetWidth != 2u &&
        provider->stringOffsetWidth != 4u) ||
       (provider->valueOffsetWidth != 1u &&
        provider->valueOffsetWidth != 2u &&
        provider->valueOffsetWidth != 4u) ||
       (provider->stringLengthWidth != 1u &&
        provider->stringLengthWidth != 2u &&
        provider->stringLengthWidth != 4u) ||
       data[78] != 0u || data[79] != 0u)
   {
      *error = "packed integer width is invalid";
      return 0;
   }
   indexCapacity = provider->indexWidth == 1u ? 0x100u :
      (provider->indexWidth == 2u ? 0x10000u : 0x100000000ULL);
   if ((uint64_t)provider->nodeCount > indexCapacity ||
       (provider->indexWidth == 2u && provider->nodeCount <= 0x100u) ||
       (provider->indexWidth == 4u && provider->nodeCount <= 0x10000u))
   {
      *error = "packed index width does not match record counts";
      return 0;
   }
   indexCapacity = provider->nodeBodyOffsetWidth == 1u ? 0x100u :
      (provider->nodeBodyOffsetWidth == 2u ?
       0x10000u : 0x100000000ULL);
   if ((uint64_t)provider->nodeBodySize > indexCapacity ||
       (provider->nodeBodyOffsetWidth == 2u &&
        provider->nodeBodySize <= 0x100u) ||
       (provider->nodeBodyOffsetWidth == 4u &&
        provider->nodeBodySize <= 0x10000u))
   {
      *error = "packed node body offset width does not match body size";
      return 0;
   }
   indexCapacity = provider->stringOffsetWidth == 1u ? 0x100u :
      (provider->stringOffsetWidth == 2u ? 0x10000u : 0x100000000ULL);
   if ((uint64_t)provider->stringSize > indexCapacity ||
       (provider->stringOffsetWidth == 2u &&
        provider->stringSize <= 0x100u) ||
       (provider->stringOffsetWidth == 4u &&
        provider->stringSize <= 0x10000u))
   {
      *error = "packed string offset width does not match string size";
      return 0;
   }
   indexCapacity = provider->valueOffsetWidth == 1u ? 0x100u :
      (provider->valueOffsetWidth == 2u ? 0x10000u : 0x100000000ULL);
   if ((uint64_t)provider->valueSize > indexCapacity ||
       (provider->valueOffsetWidth == 2u &&
        provider->valueSize <= 0x100u) ||
       (provider->valueOffsetWidth == 4u &&
        provider->valueSize <= 0x10000u))
   {
      *error = "packed value offset width does not match value size";
      return 0;
   }
   provider->attributeRecordSize =
      (uint8_t)(1u + provider->valueOffsetWidth);
   provider->externalReferenceRecordSize =
      (uint8_t)(provider->indexWidth + 2u);
   provider->referenceRecordSize =
      (uint8_t)(2u * provider->stringOffsetWidth + 1u);
   provider->fieldRecordSize =
      (uint8_t)(provider->stringOffsetWidth + provider->valueOffsetWidth);

   if (provider->nodeIdIndexOffset != OPCUA_PACKED_HEADER_SIZE ||
       !checkedSection(
          provider->nodeIdIndexOffset, provider->nodeCount,
          provider->nodeIdOffsetWidth, provider->nodeBodyIndexOffset) ||
       !checkedSection(
          provider->nodeBodyIndexOffset, provider->nodeCount,
          provider->nodeBodyOffsetWidth, provider->nodeBodyOffset) ||
       (uint64_t)provider->nodeBodyOffset + provider->nodeBodySize !=
          provider->externalReferenceOffset ||
       !checkedSection(
          provider->externalReferenceOffset,
          provider->externalReferenceCount,
          provider->externalReferenceRecordSize,
          provider->valueOffset) ||
       (uint64_t)provider->valueOffset + provider->valueSize !=
          provider->stringOffset ||
       (uint64_t)provider->stringOffset + provider->stringSize !=
          provider->size)
   {
      *error = "packed section bounds are invalid";
      return 0;
   }
   if (!validateStringPool(provider, error))
      return 0;

   for (i = 0; i < provider->nodeCount; ++i)
   {
      uint32_t idOffset = nodeIdOffset(provider, i);
      uint32_t bodyOffset = indexedNodeBodyOffset(provider, i);
      const uint8_t* nodeId;
      const uint8_t* node;
      uint32_t nodeIdLength;
      uint8_t attributeCount;
      uint8_t fieldCount;
      uint16_t referenceCount;
      uint32_t j;
      size_t bodySize;

      if ((uint64_t)idOffset != nodeIdStringSize ||
          !getString(provider, idOffset, &nodeId, &nodeIdLength))
      {
         *error = "packed NodeId index is invalid";
         return 0;
      }
      nodeIdStringSize += provider->stringLengthWidth + nodeIdLength;

      if (i > 0)
      {
         const uint8_t* previousId;
         uint32_t previousLength;
         getString(
            provider, nodeIdOffset(provider, i - 1),
            &previousId, &previousLength);
         if (compareBytes(
                previousId, previousLength, nodeId, nodeIdLength) >= 0)
         {
            *error = "packed node index is not strictly sorted";
            return 0;
         }
      }

      if ((uint64_t)bodyOffset != expectedNodeBodyOffset ||
          bodyOffset >= provider->nodeBodySize ||
          provider->nodeBodySize - bodyOffset < 3u)
      {
         *error = "packed node body index is invalid";
         return 0;
      }
      node = nodeBody(provider, bodyOffset);
      if ((node[0] & 0x80u) != 0u &&
          provider->nodeBodySize - bodyOffset < 4u)
      {
         *error = "packed node body header is invalid";
         return 0;
      }
      attributeCount = nodeAttributeCount(node);
      fieldCount = nodeFieldCount(node);
      referenceCount = nodeReferenceCount(node);
      bodySize = nodeBodySize(provider, node);
      if (expectedNodeBodyOffset + bodySize > provider->nodeBodySize)
      {
         *error = "packed node body is invalid";
         return 0;
      }
      expectedNodeBodyOffset += bodySize;
      validatedAttributeCount += attributeCount;
      validatedReferenceCount += referenceCount;
      validatedFieldCount += fieldCount;

      for (j = 0; j < attributeCount; ++j)
      {
         const uint8_t* record = nodeAttributes(node) +
            (size_t)j * provider->attributeRecordSize;
         uint32_t offset = readValueOffset(provider, record + 1);
         const uint8_t* cursor;
         if ((j > 0 && record[-provider->attributeRecordSize] >= record[0]) ||
             offset >= provider->valueSize)
         {
            *error = "packed attribute record is invalid";
            return 0;
         }
         cursor = provider->data + provider->valueOffset + offset;
         if (!skipValue(provider, &cursor, 0))
         {
            *error = "packed attribute value is invalid";
            return 0;
         }
      }

      for (j = 0; j < referenceCount; ++j)
      {
         const uint8_t* record = nodeReferences(provider, node) +
            (size_t)j * provider->referenceRecordSize;
         const uint8_t* value;
         uint32_t length;
         if (!getString(
                provider, readStringOffset(provider, record),
                &value, &length) ||
             !getString(
                provider,
                readStringOffset(
                   provider, record + provider->stringOffsetWidth),
                &value, &length) ||
             record[2u * provider->stringOffsetWidth] > 1u)
         {
            *error = "packed reference record is invalid";
            return 0;
         }
      }

      for (j = 0; j < fieldCount; ++j)
      {
         const uint8_t* record = nodeFields(provider, node) +
            (size_t)j * provider->fieldRecordSize;
         const uint8_t* value;
         const uint8_t* cursor;
         uint32_t length;
         uint32_t offset = readValueOffset(
            provider, record + provider->stringOffsetWidth);
         if (!getString(
                provider, readStringOffset(provider, record),
                &value, &length) || offset >= provider->valueSize)
         {
            *error = "packed field record is invalid";
            return 0;
         }
         cursor = provider->data + provider->valueOffset + offset;
         if (!skipValue(provider, &cursor, 0))
         {
            *error = "packed field value is invalid";
            return 0;
         }
      }
   }

   if (expectedNodeBodyOffset != provider->nodeBodySize ||
       validatedAttributeCount != provider->attributeCount ||
       validatedReferenceCount != provider->referenceCount ||
       validatedFieldCount != provider->fieldCount)
   {
      *error = "packed node body totals do not match the header";
      return 0;
   }

   indexCapacity = provider->nodeIdOffsetWidth == 1u ? 0x100u :
      (provider->nodeIdOffsetWidth == 2u ?
       0x10000u : 0x100000000ULL);
   if (nodeIdStringSize > indexCapacity ||
       (provider->nodeIdOffsetWidth == 2u && nodeIdStringSize <= 0x100u) ||
       (provider->nodeIdOffsetWidth == 4u &&
        nodeIdStringSize <= 0x10000u))
   {
      *error = "packed NodeId offset width does not match NodeId strings";
      return 0;
   }

   for (i = 0; i < provider->externalReferenceCount; ++i)
   {
      const uint8_t* external = externalReferenceRecord(provider, i);
      uint32_t sourceIndex = readIndex(external, provider->indexWidth);
      uint32_t referenceIndex = readU16(external + provider->indexWidth);
      const uint8_t* source;
      const uint8_t* reference;
      const uint8_t* target;
      uint32_t targetLength;
      uint32_t targetIndex;
      uint16_t referenceCount;

      if (sourceIndex >= provider->nodeCount)
      {
         *error = "packed external reference index is invalid";
         return 0;
      }

      source = indexedNodeBody(provider, sourceIndex);
      referenceCount = nodeReferenceCount(source);
      if (referenceIndex >= referenceCount)
      {
         *error = "packed external reference source is invalid";
         return 0;
      }

      reference = nodeReferences(provider, source) +
         (size_t)referenceIndex * provider->referenceRecordSize;
      getString(
         provider,
         readStringOffset(
            provider, reference + provider->stringOffsetWidth),
         &target, &targetLength);
      if (findNode(
            provider, (const char*)target, targetLength, &targetIndex))
      {
         *error = "packed external reference target is internal";
         return 0;
      }
   }

   return 1;
}

/* Check and return a packed-provider userdata from the Lua stack. */
static PackedProvider* checkProvider(lua_State* L, int index)
{
   return (PackedProvider*)luaL_checkudata(L, index, PROVIDER_MT);
}

/* Check and return a node, attribute, or reference view userdata. */
static PackedView* checkView(lua_State* L, int index, const char* name)
{
   return (PackedView*)luaL_checkudata(L, index, name);
}

/* Convert a relative Lua stack index to an absolute one. */
static int absoluteIndex(lua_State* L, int index)
{
   if (index > 0 || index <= LUA_REGISTRYINDEX)
      return index;
   return lua_gettop(L) + index + 1;
}

/* Keep the provider or source string alive for the lifetime of a child view. */
static void retainOwner(lua_State* L, int ownerIndex, int valueIndex)
{
   ownerIndex = absoluteIndex(L, ownerIndex);
   valueIndex = absoluteIndex(L, valueIndex);
   lua_pushvalue(L, ownerIndex);
   lua_setuservalue(L, valueIndex);
}

/* Decode one packed value and push the corresponding Lua value. */
static int decodeValue(
   lua_State* L,
   const PackedProvider* provider,
   const uint8_t** cursor,
   unsigned depth)
{
   const uint8_t* p = *cursor;
   uint8_t tag;
   if (depth > MAX_VALUE_DEPTH)
      return luaL_error(L, "packed value nesting is too deep");

   tag = *p++;
   switch (tag)
   {
      case VALUE_FALSE:
         lua_pushboolean(L, 0);
         break;

      case VALUE_TRUE:
         lua_pushboolean(L, 1);
         break;

      case VALUE_INTEGER:
      {
         int64_t value = (int64_t)readU64(p);
         p += 8;
         lua_pushinteger(L, (lua_Integer)value);
         break;
      }

      case VALUE_NUMBER:
      {
         uint64_t bits = readU64(p);
         double value;
         p += 8;
         memcpy(&value, &bits, sizeof(value));
         lua_pushnumber(L, (lua_Number)value);
         break;
      }

      case VALUE_STRING:
      {
         const uint8_t* value;
         uint32_t length;
         getString(
            provider, readStringOffset(provider, p), &value, &length);
         p += provider->stringOffsetWidth;
         lua_pushlstring(L, (const char*)value, length);
         break;
      }

      case VALUE_TABLE:
      {
         uint32_t count = readU32(p);
         uint32_t i;
         p += 4;
         lua_createtable(L, 0, (int)count);
         for (i = 0; i < count; ++i)
         {
            decodeValue(L, provider, &p, depth + 1);
            decodeValue(L, provider, &p, depth + 1);
            lua_settable(L, -3);
         }
         break;
      }

      default:
         return luaL_error(L, "invalid packed value tag");
   }

   *cursor = p;
   return 1;
}

/* Find a node with binary search over the NodeId-sorted node section. */
static int findNode(
   const PackedProvider* provider,
   const char* nodeId,
   size_t nodeIdLength,
   uint32_t* result)
{
   uint32_t first = 0;
   uint32_t last = provider->nodeCount;
   while (first < last)
   {
      uint32_t middle = first + (last - first) / 2;
      const uint8_t* candidate;
      uint32_t candidateLength;
      int comparison;
      getString(
         provider, nodeIdOffset(provider, middle),
         &candidate, &candidateLength);
      comparison = compareBytes(
         (const uint8_t*)nodeId, nodeIdLength,
         candidate, candidateLength);
      if (comparison == 0)
      {
         *result = middle;
         return 1;
      }
      if (comparison < 0)
         last = middle;
      else
         first = middle + 1;
   }
   return 0;
}

/* Find an attribute with binary search over one node's sorted attributes. */
static int findAttribute(
   const PackedProvider* provider,
   uint32_t nodeOffset,
   uint8_t attributeId,
   const uint8_t** result)
{
   const uint8_t* node = nodeBody(provider, nodeOffset);
   const uint8_t* attributes = nodeAttributes(node);
   uint8_t count = nodeAttributeCount(node);
   uint32_t first = 0;
   uint32_t last = count;
   while (first < last)
   {
      uint32_t middle = first + (last - first) / 2;
      const uint8_t* record = attributes +
         (size_t)middle * provider->attributeRecordSize;
      uint8_t candidate = record[0];
      if (candidate == attributeId)
      {
         *result = record;
         return 1;
      }
      if (attributeId < candidate)
         last = middle;
      else
         first = middle + 1;
   }
   return 0;
}

/* Convert a standard OPC UA attribute name to its numeric AttributeId. */
static int attributeNameToId(const char* name)
{
   static const char* names[] = {
      NULL,
      "NodeId", "NodeClass", "BrowseName", "DisplayName", "Description",
      "WriteMask", "UserWriteMask", "IsAbstract", "Symmetric",
      "InverseName", "ContainsNoLoops", "EventNotifier", "Value",
      "DataType", "Rank", "ArrayDimensions", "AccessLevel",
      "UserAccessLevel", "MinimumSamplingInterval", "Historizing",
      "Executable", "UserExecutable", "DataTypeDefinition",
      "RolePermissions", "UserRolePermissions", "AccessRestrictions",
      "AccessLevelEx",
   };
   unsigned i;
   for (i = 1; i < sizeof(names) / sizeof(names[0]); ++i)
   {
      if (strcmp(name, names[i]) == 0)
         return (int)i;
   }
   return 0;
}

/* Decode and push one node attribute; return zero when it is absent. */
static int pushAttribute(
   lua_State* L,
   const PackedProvider* provider,
   uint32_t nodeOffset,
   uint8_t attributeId)
{
   const uint8_t* record;
   const uint8_t* cursor;
   if (!findAttribute(provider, nodeOffset, attributeId, &record))
      return 0;
   cursor = provider->data + provider->valueOffset +
      readValueOffset(provider, record + 1);
   decodeValue(L, provider, &cursor, 0);
   return 1;
}

/* Materialize one packed reference as a Lua reference table. */
static int pushReference(
   lua_State* L,
   const PackedProvider* provider,
   const uint8_t* record)
{
   const uint8_t* value;
   uint32_t length;
   lua_createtable(L, 0, 3);

   getString(
      provider, readStringOffset(provider, record), &value, &length);
   lua_pushlstring(L, (const char*)value, length);
   lua_setfield(L, -2, "type");

   getString(
      provider,
      readStringOffset(provider, record + provider->stringOffsetWidth),
      &value, &length);
   lua_pushlstring(L, (const char*)value, length);
   lua_setfield(L, -2, "target");

   lua_pushboolean(L, record[2u * provider->stringOffsetWidth] != 0);
   lua_setfield(L, -2, "isForward");
   return 1;
}

/* Create an owning Lua view over one node using the requested metatable. */
static int pushView(
   lua_State* L,
   PackedProvider* provider,
   uint32_t nodeOffset,
   const char* metatable,
   int ownerIndex)
{
   PackedView* view = (PackedView*)lua_newuserdata(L, sizeof(PackedView));
   view->provider = provider;
   view->nodeOffset = nodeOffset;
   luaL_setmetatable(L, metatable);
   retainOwner(L, ownerIndex, -1);
   return 1;
}

/* Create a Lua node view and retain its provider owner. */
static int pushNode(
   lua_State* L,
   PackedProvider* provider,
   uint32_t nodeIndex,
   int ownerIndex)
{
   return pushView(
      L, provider, indexedNodeBodyOffset(provider, nodeIndex),
      NODE_MT, ownerIndex);
}

/* Implement provider:getNode(NodeId). */
static int providerGetNode(lua_State* L)
{
   PackedProvider* provider = checkProvider(L, 1);
   size_t length;
   const char* nodeId = luaL_checklstring(L, 2, &length);
   uint32_t index;
   if (!findNode(provider, nodeId, length, &index))
   {
      lua_pushnil(L);
      return 1;
   }
   return pushNode(L, provider, index, 1);
}

/* Resolve an encoding alias or datatype to its canonical datatype node. */
static int providerGetTypeInfo(lua_State* L)
{
   PackedProvider* provider = checkProvider(L, 1);
   size_t length;
   const char* nodeId = luaL_checklstring(L, 2, &length);
   uint32_t index;
   PackedView view;
   if (!findNode(provider, nodeId, length, &index))
   {
      lua_pushnil(L);
      return 1;
   }
   view.provider = provider;
   view.nodeOffset = indexedNodeBodyOffset(provider, index);
   if (!findTypeInfoNode(L, &view, &index))
   {
      lua_pushnil(L);
      return 1;
   }
   return pushNode(L, provider, index, 1);
}

/* Yield the next NodeId and node view for provider:iterateNodes(). */
static int providerNodesIterator(lua_State* L)
{
   PackedProvider* provider =
      checkProvider(L, lua_upvalueindex(1));
   uint32_t* position =
      (uint32_t*)lua_touserdata(L, lua_upvalueindex(2));
   const uint8_t* nodeId;
   uint32_t nodeIdLength;
   uint32_t index;

   if (*position >= provider->nodeCount)
      return 0;
   index = (*position)++;
   getString(
      provider, nodeIdOffset(provider, index),
      &nodeId, &nodeIdLength);
   lua_pushlstring(L, (const char*)nodeId, nodeIdLength);
   pushNode(L, provider, index, lua_upvalueindex(1));
   return 2;
}

/* Create an iterator over every node in packed NodeId order. */
static int providerIterateNodes(lua_State* L)
{
   checkProvider(L, 1);
   lua_pushvalue(L, 1);
   {
      uint32_t* position = (uint32_t*)lua_newuserdata(L, sizeof(uint32_t));
      *position = 0;
   }
   lua_pushcclosure(L, providerNodesIterator, 2);
   return 1;
}

/* Return blob section sizes and record counts for diagnostics. */
static int providerStats(lua_State* L)
{
   PackedProvider* provider = checkProvider(L, 1);
   lua_createtable(L, 0, 14);
#define SET_STAT(field, value) \
   lua_pushinteger(L, (lua_Integer)(value)); \
   lua_setfield(L, -2, (field))
   SET_STAT("BlobSize", provider->size);
   SET_STAT("NodeCount", provider->nodeCount);
   SET_STAT("AttributeCount", provider->attributeCount);
   SET_STAT("ReferenceCount", provider->referenceCount);
   SET_STAT("ExternalReferenceCount", provider->externalReferenceCount);
   SET_STAT("FieldCount", provider->fieldCount);
   SET_STAT("StringPoolSize", provider->stringSize);
   SET_STAT("NodeBodySize", provider->nodeBodySize);
   SET_STAT("IndexWidth", provider->indexWidth);
   SET_STAT("NodeIdOffsetWidth", provider->nodeIdOffsetWidth);
   SET_STAT("NodeBodyOffsetWidth", provider->nodeBodyOffsetWidth);
   SET_STAT("StringOffsetWidth", provider->stringOffsetWidth);
   SET_STAT("ValueOffsetWidth", provider->valueOffsetWidth);
   SET_STAT("StringLengthWidth", provider->stringLengthWidth);
#undef SET_STAT
   return 1;
}

/* Yield the next inverse reference whose target belongs to another provider. */
static int providerExternalReferencesIterator(lua_State* L)
{
   PackedProvider* provider =
      checkProvider(L, lua_upvalueindex(1));
   uint32_t* position =
      (uint32_t*)lua_touserdata(L, lua_upvalueindex(2));
   const uint8_t* external;
   const uint8_t* source;
   const uint8_t* sourceId;
   uint32_t sourceIdLength;
   uint32_t sourceIndex;
   uint32_t referenceIndex;

   if (*position >= provider->externalReferenceCount)
      return 0;

   external = externalReferenceRecord(provider, (*position)++);
   sourceIndex = readIndex(external, provider->indexWidth);
   referenceIndex = readU16(external + provider->indexWidth);
   source = indexedNodeBody(provider, sourceIndex);
   getString(
      provider, nodeIdOffset(provider, sourceIndex),
      &sourceId, &sourceIdLength);
   lua_pushlstring(L, (const char*)sourceId, sourceIdLength);
   pushReference(
      L, provider,
      nodeReferences(provider, source) +
         (size_t)referenceIndex * provider->referenceRecordSize);
   return 2;
}

/* Create an iterator over the blob's external-reference index. */
static int providerIterateExternalReferences(lua_State* L)
{
   checkProvider(L, 1);
   lua_pushvalue(L, 1);
   {
      uint32_t* position = (uint32_t*)lua_newuserdata(L, sizeof(uint32_t));
      *position = 0;
   }
   lua_pushcclosure(L, providerExternalReferencesIterator, 2);
   return 1;
}

/* Dispatch provider methods and support provider[NodeId] lookup. */
static int providerIndex(lua_State* L)
{
   const char* key = luaL_checkstring(L, 2);
   if (strcmp(key, "getNode") == 0)
      lua_pushcfunction(L, providerGetNode);
   else if (strcmp(key, "getTypeInfo") == 0)
      lua_pushcfunction(L, providerGetTypeInfo);
   else if (strcmp(key, "iterateNodes") == 0)
      lua_pushcfunction(L, providerIterateNodes);
   else if (strcmp(key, "getStats") == 0)
      lua_pushcfunction(L, providerStats);
   else if (strcmp(key, "iterateExternalReferences") == 0)
      lua_pushcfunction(L, providerIterateExternalReferences);
   else
      return providerGetNode(L);
   return 1;
}

/* Implement pairs(provider) by returning the packed-node iterator. */
static int providerPairs(lua_State* L)
{
   return providerIterateNodes(L);
}

/* Resolve attrs[AttributeId] and attrs.AttributeName lookups. */
static int attrsIndex(lua_State* L)
{
   PackedView* view = checkView(L, 1, ATTRS_MT);
   int attributeId;
   if (lua_type(L, 2) == LUA_TNUMBER)
      attributeId = (int)luaL_checkinteger(L, 2);
   else
      attributeId = attributeNameToId(luaL_checkstring(L, 2));
   if (attributeId <= 0 || attributeId > UINT8_MAX ||
       !pushAttribute(
          L, view->provider, view->nodeOffset, (uint8_t)attributeId))
      lua_pushnil(L);
   return 1;
}

/* Yield the next numeric AttributeId and decoded raw attribute value. */
static int attrsIterator(lua_State* L)
{
   PackedView* view = checkView(L, lua_upvalueindex(1), ATTRS_MT);
   uint32_t* position =
      (uint32_t*)lua_touserdata(L, lua_upvalueindex(2));
   const uint8_t* node = nodeBody(view->provider, view->nodeOffset);
   uint8_t count = nodeAttributeCount(node);
   const uint8_t* record;
   const uint8_t* cursor;

   if (*position >= count)
      return 0;
   record = nodeAttributes(node) +
      (size_t)(*position)++ * view->provider->attributeRecordSize;
   lua_pushinteger(L, record[0]);
   cursor = view->provider->data + view->provider->valueOffset +
      readValueOffset(view->provider, record + 1);
   decodeValue(L, view->provider, &cursor, 0);
   return 2;
}

/* Implement pairs(node.Attrs). */
static int attrsPairs(lua_State* L)
{
   checkView(L, 1, ATTRS_MT);
   lua_pushvalue(L, 1);
   {
      uint32_t* position = (uint32_t*)lua_newuserdata(L, sizeof(uint32_t));
      *position = 0;
   }
   lua_pushcclosure(L, attrsIterator, 2);
   return 1;
}

/* Return the number of references owned by a node. */
static int refsLength(lua_State* L)
{
   PackedView* view = checkView(L, 1, REFS_MT);
   const uint8_t* node = nodeBody(view->provider, view->nodeOffset);
   lua_pushinteger(L, nodeReferenceCount(node));
   return 1;
}

/* Resolve a one-based reference index from node.Refs. */
static int refsIndex(lua_State* L)
{
   PackedView* view = checkView(L, 1, REFS_MT);
   lua_Integer requested = luaL_checkinteger(L, 2);
   const uint8_t* node = nodeBody(view->provider, view->nodeOffset);
   uint16_t count = nodeReferenceCount(node);
   if (requested < 1 || (uint64_t)requested > count)
   {
      lua_pushnil(L);
      return 1;
   }
   return pushReference(
      L, view->provider,
      nodeReferences(view->provider, node) +
         ((size_t)requested - 1u) * view->provider->referenceRecordSize);
}

/* Yield the next one-based reference index and materialized reference. */
static int refsIterator(lua_State* L)
{
   PackedView* view = checkView(L, lua_upvalueindex(1), REFS_MT);
   uint32_t* position =
      (uint32_t*)lua_touserdata(L, lua_upvalueindex(2));
   const uint8_t* node = nodeBody(view->provider, view->nodeOffset);
   uint16_t count = nodeReferenceCount(node);
   if (*position >= count)
      return 0;
   lua_pushinteger(L, (lua_Integer)*position + 1);
   pushReference(
      L, view->provider,
      nodeReferences(view->provider, node) +
         (size_t)(*position)++ * view->provider->referenceRecordSize);
   return 2;
}

/* Implement pairs(node.Refs). */
static int refsPairs(lua_State* L)
{
   checkView(L, 1, REFS_MT);
   lua_pushvalue(L, 1);
   {
      uint32_t* position = (uint32_t*)lua_newuserdata(L, sizeof(uint32_t));
      *position = 0;
   }
   lua_pushcclosure(L, refsIterator, 2);
   return 1;
}

/* Implement node:getAttribute() with an explicit found result. */
static int nodeGetAttribute(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   int attributeId;
   if (lua_type(L, 2) == LUA_TNUMBER)
      attributeId = (int)luaL_checkinteger(L, 2);
   else
      attributeId = attributeNameToId(luaL_checkstring(L, 2));
   if (attributeId <= 0 || attributeId > UINT8_MAX)
   {
      lua_pushboolean(L, 0);
      lua_pushnil(L);
      return 2;
   }
   lua_pushboolean(L, 1);
   if (!pushAttribute(
          L, view->provider, view->nodeOffset, (uint8_t)attributeId))
   {
      lua_pop(L, 1);
      lua_pushboolean(L, 0);
      lua_pushnil(L);
   }
   return 2;
}

/* Create the iterator returned by node:iterateAttributes(). */
static int nodeIterateAttributes(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   pushView(L, view->provider, view->nodeOffset, ATTRS_MT, 1);
   lua_replace(L, 1);
   lua_settop(L, 1);
   return attrsPairs(L);
}

/* Create the iterator returned by node:iterateReferences(). */
static int nodeIterateReferences(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   pushView(L, view->provider, view->nodeOffset, REFS_MT, 1);
   lua_replace(L, 1);
   lua_settop(L, 1);
   return refsPairs(L);
}

/* Find an exact reference tuple owned by a node. */
static int nodeGetReference(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   size_t typeLength;
   size_t targetLength;
   const char* type = luaL_checklstring(L, 2, &typeLength);
   const char* target = luaL_checklstring(L, 3, &targetLength);
   int isForward = lua_toboolean(L, 4);
   const uint8_t* node = nodeBody(view->provider, view->nodeOffset);
   const uint8_t* references = nodeReferences(view->provider, node);
   uint16_t count = nodeReferenceCount(node);
   uint16_t i;
   for (i = 0; i < count; ++i)
   {
      const uint8_t* record = references +
         (size_t)i * view->provider->referenceRecordSize;
      const uint8_t* candidateType;
      const uint8_t* candidateTarget;
      uint32_t candidateTypeLength;
      uint32_t candidateTargetLength;
      getString(
         view->provider, readStringOffset(view->provider, record),
         &candidateType, &candidateTypeLength);
      getString(
         view->provider,
         readStringOffset(
            view->provider,
            record + view->provider->stringOffsetWidth),
         &candidateTarget, &candidateTargetLength);
      if (compareBytes(
             (const uint8_t*)type, typeLength,
             candidateType, candidateTypeLength) == 0 &&
          compareBytes(
             (const uint8_t*)target, targetLength,
             candidateTarget, candidateTargetLength) == 0 &&
          (record[2u * view->provider->stringOffsetWidth] != 0) == isForward)
      {
         lua_pushboolean(L, 1);
         pushReference(L, view->provider, record);
         return 2;
      }
   }
   lua_pushboolean(L, 0);
   lua_pushnil(L);
   return 2;
}

/* Find a named metadata field in one node's packed field records. */
static int findField(
   const PackedView* view,
   const char* key,
   size_t keyLength,
   const uint8_t** result)
{
   const uint8_t* node = nodeBody(view->provider, view->nodeOffset);
   const uint8_t* fields = nodeFields(view->provider, node);
   uint8_t count = nodeFieldCount(node);
   uint16_t i;
   for (i = 0; i < count; ++i)
   {
      const uint8_t* record = fields +
         (size_t)i * view->provider->fieldRecordSize;
      const uint8_t* candidate;
      uint32_t candidateLength;
      getString(
         view->provider, readStringOffset(view->provider, record),
         &candidate, &candidateLength);
      if (compareBytes(
             (const uint8_t*)key, keyLength,
             candidate, candidateLength) == 0)
      {
         *result = record;
         return 1;
      }
   }
   return 0;
}

/* Decode and push a named metadata field when present. */
static int pushField(lua_State* L, const PackedView* view, const char* key)
{
   const uint8_t* record;
   const uint8_t* cursor;
   if (!findField(view, key, strlen(key), &record))
      return 0;
   cursor = view->provider->data + view->provider->valueOffset +
      readValueOffset(
         view->provider, record + view->provider->stringOffsetWidth);
   decodeValue(L, view->provider, &cursor, 0);
   return 1;
}

/* Follow a node's DataTypeId field to its canonical datatype node. */
static int findTypeInfoNode(
   lua_State* L,
   const PackedView* view,
   uint32_t* result)
{
   const char* dataTypeId;
   size_t length;
   int found;
   if (!pushField(L, view, "DataTypeId"))
      return 0;
   dataTypeId = lua_tolstring(L, -1, &length);
   if (dataTypeId == NULL)
   {
      lua_pop(L, 1);
      return 0;
   }
   found = findNode(view->provider, dataTypeId, length, result);
   lua_pop(L, 1);
   return found;
}

/* Return the node's standard DataTypeDefinition attribute. */
static int nodeGetDefinition(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   if (!pushAttribute(L, view->provider, view->nodeOffset, 23u))
      lua_pushnil(L);
   return 1;
}

/* Yield the next locally declared DataTypeDefinition field. */
static int definitionFieldsIterator(lua_State* L)
{
   uint32_t* position =
      (uint32_t*)lua_touserdata(L, lua_upvalueindex(2));
   uint32_t index = ++(*position);
   lua_pushinteger(L, (lua_Integer)index);
   lua_rawgeti(L, lua_upvalueindex(1), (lua_Integer)index);
   if (lua_isnil(L, -1))
   {
      lua_pop(L, 2);
      return 0;
   }
   return 2;
}

/* Iterate locally declared fields in the standard datatype definition. */
static int nodeIterateFields(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   size_t count;
   if (!pushAttribute(L, view->provider, view->nodeOffset, 23u))
   {
      lua_pushnil(L);
      lua_pushinteger(L, 0);
      return 2;
   }
   if (!lua_istable(L, -1))
      return luaL_error(L, "DataTypeDefinition is not a table");

   count = lua_rawlen(L, -1);
   lua_pushvalue(L, -1);
   {
      uint32_t* position =
         (uint32_t*)lua_newuserdata(L, sizeof(uint32_t));
      *position = 0;
   }
   lua_pushcclosure(L, definitionFieldsIterator, 2);
   lua_pushinteger(L, (lua_Integer)count);
   return 2;
}

/* Return the canonical datatype node used as this node's TypeInfo source. */
static int nodeGetTypeInfo(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   uint32_t index;
   if (!findTypeInfoNode(L, view, &index))
   {
      lua_pushnil(L);
      return 1;
   }
   return pushNode(L, view->provider, index, 1);
}

/* Return the direct base datatype NodeId stored with a canonical datatype. */
static int nodeGetBaseId(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   if (!pushField(L, view, "BaseId"))
      lua_pushnil(L);
   return 1;
}

/* Return the canonical datatype NodeId represented by this node. */
static int nodeGetDataTypeNodeId(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   if (!pushField(L, view, "DataTypeId") &&
       !pushAttribute(L, view->provider, view->nodeOffset, 1u))
      lua_pushnil(L);
   return 1;
}

/* Return the Binary or JSON encoding NodeId for a datatype. */
static int nodeGetEncodingNodeId(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   const char* kind = luaL_checkstring(L, 2);
   const char* field = NULL;
   if (strcmp(kind, "Binary") == 0 ||
       strcmp(kind, "Default Binary") == 0)
      field = "BinaryId";
   else if (strcmp(kind, "Json") == 0 ||
            strcmp(kind, "JSON") == 0 ||
            strcmp(kind, "Default JSON") == 0)
      field = "JsonId";
   if (field == NULL || !pushField(L, view, field))
      lua_pushnil(L);
   return 1;
}

/* Dispatch node properties, methods, and packed metadata fields. */
static int nodeIndex(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   size_t keyLength;
   const char* key = luaL_checklstring(L, 2, &keyLength);

   if (strcmp(key, "Attrs") == 0)
      return pushView(L, view->provider, view->nodeOffset, ATTRS_MT, 1);
   if (strcmp(key, "Refs") == 0)
      return pushView(L, view->provider, view->nodeOffset, REFS_MT, 1);
   if (strcmp(key, "getAttribute") == 0)
      lua_pushcfunction(L, nodeGetAttribute);
   else if (strcmp(key, "iterateAttributes") == 0)
      lua_pushcfunction(L, nodeIterateAttributes);
   else if (strcmp(key, "getReference") == 0)
      lua_pushcfunction(L, nodeGetReference);
   else if (strcmp(key, "iterateReferences") == 0)
      lua_pushcfunction(L, nodeIterateReferences);
   else if (strcmp(key, "getDefinition") == 0)
      lua_pushcfunction(L, nodeGetDefinition);
   else if (strcmp(key, "iterateFields") == 0)
      lua_pushcfunction(L, nodeIterateFields);
   else if (strcmp(key, "getTypeInfo") == 0)
      lua_pushcfunction(L, nodeGetTypeInfo);
   else if (strcmp(key, "getBaseId") == 0)
      lua_pushcfunction(L, nodeGetBaseId);
   else if (strcmp(key, "getDataTypeNodeId") == 0)
      lua_pushcfunction(L, nodeGetDataTypeNodeId);
   else if (strcmp(key, "getEncodingNodeId") == 0)
      lua_pushcfunction(L, nodeGetEncodingNodeId);
   else
   {
      const uint8_t* record;
      const uint8_t* cursor;
      if (!findField(view, key, keyLength, &record))
      {
         lua_pushnil(L);
         return 1;
      }
      cursor = view->provider->data + view->provider->valueOffset +
         readValueOffset(
            view->provider, record + view->provider->stringOffsetWidth);
      decodeValue(L, view->provider, &cursor, 0);
   }
   return 1;
}

/* Yield Attrs, Refs, and then every packed metadata field for pairs(node). */
static int nodePairsIterator(lua_State* L)
{
   PackedView* view = checkView(L, lua_upvalueindex(1), NODE_MT);
   uint32_t* position =
      (uint32_t*)lua_touserdata(L, lua_upvalueindex(2));
   const uint8_t* node = nodeBody(view->provider, view->nodeOffset);
   const uint8_t* fields = nodeFields(view->provider, node);
   uint8_t count = nodeFieldCount(node);

   if (*position == 0)
   {
      ++(*position);
      lua_pushliteral(L, "Attrs");
      pushView(
         L, view->provider, view->nodeOffset,
         ATTRS_MT, lua_upvalueindex(1));
      return 2;
   }
   if (*position == 1)
   {
      ++(*position);
      lua_pushliteral(L, "Refs");
      pushView(
         L, view->provider, view->nodeOffset,
         REFS_MT, lua_upvalueindex(1));
      return 2;
   }
   if (*position - 2u < count)
   {
      const uint8_t* record = fields +
         (size_t)(*position - 2u) * view->provider->fieldRecordSize;
      const uint8_t* key;
      const uint8_t* cursor;
      uint32_t keyLength;
      ++(*position);
      getString(
         view->provider, readStringOffset(view->provider, record),
         &key, &keyLength);
      lua_pushlstring(L, (const char*)key, keyLength);
      cursor = view->provider->data + view->provider->valueOffset +
         readValueOffset(
            view->provider, record + view->provider->stringOffsetWidth);
      decodeValue(L, view->provider, &cursor, 0);
      return 2;
   }
   return 0;
}

/* Implement pairs(node). */
static int nodePairs(lua_State* L)
{
   checkView(L, 1, NODE_MT);
   lua_pushvalue(L, 1);
   {
      uint32_t* position = (uint32_t*)lua_newuserdata(L, sizeof(uint32_t));
      *position = 0;
   }
   lua_pushcclosure(L, nodePairsIterator, 2);
   return 1;
}

/* Validate and mount a packed blob supplied as a Lua string. */
static int packedOpen(lua_State* L)
{
   size_t size;
   const char* source = luaL_checklstring(L, 1, &size);
   const char* error = NULL;
   PackedProvider* provider =
      (PackedProvider*)lua_newuserdata(L, sizeof(PackedProvider));
   memset(provider, 0, sizeof(*provider));
   provider->data = (const uint8_t*)source;
   provider->size = size;

   if (!validateProvider(provider, PACKED_CHECKSUM_VERIFY, &error))
      return luaL_error(L, "cannot mount packed address space: %s", error);

   luaL_setmetatable(L, PROVIDER_MT);
   retainOwner(L, 1, -1);
   return 1;
}

/* Mount a packed model compiled directly into the firmware. */
static int packedOpenBuiltin(lua_State* L)
{
   const char* name = luaL_checkstring(L, 1);
   const char* error = NULL;
   PackedProvider* provider;
   if (strcmp(name, "ns0") != 0)
      return luaL_error(L, "unknown built-in packed address space: %s", name);

   provider = (PackedProvider*)lua_newuserdata(L, sizeof(PackedProvider));
   memset(provider, 0, sizeof(*provider));
   provider->data = opcua_ns0_blob;
   provider->size = opcua_ns0_blob_size;
   if (!validateProvider(provider, PACKED_CHECKSUM_SKIP, &error))
      return luaL_error(
         L, "cannot mount built-in packed address space: %s", error);
   luaL_setmetatable(L, PROVIDER_MT);
   return 1;
}

/* Create one Lua userdata metatable with optional index and pairs handlers. */
static void createMetatable(
   lua_State* L,
   const char* name,
   lua_CFunction index,
   lua_CFunction pairs)
{
   luaL_newmetatable(L, name);
   if (index != NULL)
   {
      lua_pushcfunction(L, index);
      lua_setfield(L, -2, "__index");
   }
   if (pairs != NULL)
   {
      lua_pushcfunction(L, pairs);
      lua_setfield(L, -2, "__pairs");
   }
   lua_pop(L, 1);
}

/* Register and return the opcua_ns0 Lua module. */
int luaopen_opcua_ns0(lua_State* L)
{
   createMetatable(L, PROVIDER_MT, providerIndex, providerPairs);
   createMetatable(L, NODE_MT, nodeIndex, nodePairs);
   createMetatable(L, ATTRS_MT, attrsIndex, attrsPairs);
   createMetatable(L, REFS_MT, refsIndex, refsPairs);

   luaL_getmetatable(L, REFS_MT);
   lua_pushcfunction(L, refsLength);
   lua_setfield(L, -2, "__len");
   lua_pop(L, 1);

   lua_createtable(L, 0, 2);
   lua_pushcfunction(L, packedOpen);
   lua_setfield(L, -2, "open");
   lua_pushcfunction(L, packedOpenBuiltin);
   lua_setfield(L, -2, "openBuiltin");
   return 1;
}

/* Register opcua_ns0 in firmware builds that use static Lua modules. */
void luaopen_opcua_ns0_static(lua_State* L)
{
   luaL_requiref(L, "opcua_ns0", luaopen_opcua_ns0, 1);
   lua_pop(L, 1);
}

/* Compatibility entry point used by current BAS integration code. */
void luaopen_opcua_packed_static(lua_State* L)
{
   luaopen_opcua_ns0_static(L);
}
