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
   const uint8_t* data;
   size_t size;
   uint32_t nodeCount;
   uint32_t nodeOffset;
   uint32_t attributeCount;
   uint32_t attributeOffset;
   uint32_t referenceCount;
   uint32_t referenceOffset;
   uint32_t externalReferenceCount;
   uint32_t externalReferenceOffset;
   uint32_t fieldCount;
   uint32_t fieldOffset;
   uint32_t valueOffset;
   uint32_t valueSize;
   uint32_t stringOffset;
   uint32_t stringSize;
} PackedProvider;

typedef struct PackedView
{
   PackedProvider* provider;
   uint32_t nodeIndex;
} PackedView;

static uint16_t readU16(const uint8_t* p)
{
   return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t readU32(const uint8_t* p)
{
   return (uint32_t)p[0] |
      ((uint32_t)p[1] << 8) |
      ((uint32_t)p[2] << 16) |
      ((uint32_t)p[3] << 24);
}

static uint64_t readU64(const uint8_t* p)
{
   uint64_t value = 0;
   unsigned i;
   for (i = 0; i < 8; ++i)
      value |= (uint64_t)p[i] << (i * 8);
   return value;
}

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

static int checkedSection(
   uint32_t offset,
   uint32_t count,
   uint32_t recordSize,
   uint32_t expectedEnd)
{
   uint64_t end = (uint64_t)offset + (uint64_t)count * recordSize;
   return end == expectedEnd;
}

static int getString(
   const PackedProvider* provider,
   uint32_t relativeOffset,
   const uint8_t** value,
   uint32_t* length)
{
   uint64_t entry = (uint64_t)provider->stringOffset + relativeOffset;
   uint32_t size;
   if (relativeOffset > provider->stringSize ||
       entry + 4u > provider->size)
      return 0;

   size = readU32(provider->data + (size_t)entry);
   if ((uint64_t)relativeOffset + 4u + size > provider->stringSize)
      return 0;

   *value = provider->data + (size_t)entry + 4u;
   *length = size;
   return 1;
}

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
         if ((size_t)(end - p) < 4u ||
             !getString(provider, readU32(p), &value, &length))
            return 0;
         p += 4;
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

static const uint8_t* nodeRecord(
   const PackedProvider* provider,
   uint32_t index)
{
   return provider->data + provider->nodeOffset +
      (size_t)index * OPCUA_PACKED_NODE_RECORD_SIZE;
}

static const uint8_t* attributeRecord(
   const PackedProvider* provider,
   uint32_t index)
{
   return provider->data + provider->attributeOffset +
      (size_t)index * OPCUA_PACKED_ATTRIBUTE_RECORD_SIZE;
}

static const uint8_t* referenceRecord(
   const PackedProvider* provider,
   uint32_t index)
{
   return provider->data + provider->referenceOffset +
      (size_t)index * OPCUA_PACKED_REFERENCE_RECORD_SIZE;
}

static const uint8_t* externalReferenceRecord(
   const PackedProvider* provider,
   uint32_t index)
{
   return provider->data + provider->externalReferenceOffset +
      (size_t)index * OPCUA_PACKED_EXTERNAL_REFERENCE_RECORD_SIZE;
}

static const uint8_t* fieldRecord(
   const PackedProvider* provider,
   uint32_t index)
{
   return provider->data + provider->fieldOffset +
      (size_t)index * OPCUA_PACKED_FIELD_RECORD_SIZE;
}

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

static int validateProvider(PackedProvider* provider, const char** error)
{
   const uint8_t* data = provider->data;
   uint32_t totalSize;
   uint32_t checksum;
   uint32_t i;

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
   if (crc32Blob(data, provider->size) != checksum)
   {
      *error = "packed CRC mismatch";
      return 0;
   }

   provider->nodeCount = readU32(data + 16);
   provider->nodeOffset = readU32(data + 20);
   provider->attributeCount = readU32(data + 24);
   provider->attributeOffset = readU32(data + 28);
   provider->referenceCount = readU32(data + 32);
   provider->referenceOffset = readU32(data + 36);
   provider->externalReferenceCount = readU32(data + 40);
   provider->externalReferenceOffset = readU32(data + 44);
   provider->fieldCount = readU32(data + 48);
   provider->fieldOffset = readU32(data + 52);
   provider->valueOffset = readU32(data + 56);
   provider->valueSize = readU32(data + 60);
   provider->stringOffset = readU32(data + 64);
   provider->stringSize = readU32(data + 68);

   if (provider->nodeOffset != OPCUA_PACKED_HEADER_SIZE ||
       !checkedSection(
          provider->nodeOffset, provider->nodeCount,
          OPCUA_PACKED_NODE_RECORD_SIZE, provider->attributeOffset) ||
       !checkedSection(
          provider->attributeOffset, provider->attributeCount,
          OPCUA_PACKED_ATTRIBUTE_RECORD_SIZE, provider->referenceOffset) ||
       !checkedSection(
          provider->referenceOffset, provider->referenceCount,
          OPCUA_PACKED_REFERENCE_RECORD_SIZE,
          provider->externalReferenceOffset) ||
       !checkedSection(
          provider->externalReferenceOffset,
          provider->externalReferenceCount,
          OPCUA_PACKED_EXTERNAL_REFERENCE_RECORD_SIZE,
          provider->fieldOffset) ||
       !checkedSection(
          provider->fieldOffset, provider->fieldCount,
          OPCUA_PACKED_FIELD_RECORD_SIZE, provider->valueOffset) ||
       (uint64_t)provider->valueOffset + provider->valueSize !=
          provider->stringOffset ||
       (uint64_t)provider->stringOffset + provider->stringSize !=
          provider->size)
   {
      *error = "packed section bounds are invalid";
      return 0;
   }

   for (i = 0; i < provider->nodeCount; ++i)
   {
      const uint8_t* record = nodeRecord(provider, i);
      const uint8_t* nodeId;
      uint32_t nodeIdLength;
      uint32_t attributeStart = readU32(record + 4);
      uint32_t referenceStart = readU32(record + 8);
      uint16_t attributeCount = readU16(record + 12);
      uint16_t referenceCount = readU16(record + 14);
      uint32_t fieldStart = readU32(record + 16);
      uint16_t fieldCount = readU16(record + 20);

      if (!getString(provider, readU32(record), &nodeId, &nodeIdLength) ||
          (uint64_t)attributeStart + attributeCount >
             provider->attributeCount ||
          (uint64_t)referenceStart + referenceCount >
             provider->referenceCount ||
          (uint64_t)fieldStart + fieldCount > provider->fieldCount)
      {
         *error = "packed node record is invalid";
         return 0;
      }

      if (i > 0)
      {
         const uint8_t* previous = nodeRecord(provider, i - 1);
         const uint8_t* previousId;
         uint32_t previousLength;
         if (!getString(
                provider, readU32(previous), &previousId, &previousLength) ||
             compareBytes(
                previousId, previousLength, nodeId, nodeIdLength) >= 0)
         {
            *error = "packed node index is not strictly sorted";
            return 0;
         }
      }
   }

   for (i = 0; i < provider->attributeCount; ++i)
   {
      const uint8_t* record = attributeRecord(provider, i);
      uint32_t offset = readU32(record + 4);
      const uint8_t* cursor;
      if (offset < provider->valueOffset ||
          offset >= provider->valueOffset + provider->valueSize)
      {
         *error = "packed attribute value offset is invalid";
         return 0;
      }
      cursor = provider->data + offset;
      if (!skipValue(provider, &cursor, 0))
      {
         *error = "packed attribute value is invalid";
         return 0;
      }
   }

   for (i = 0; i < provider->referenceCount; ++i)
   {
      const uint8_t* record = referenceRecord(provider, i);
      const uint8_t* value;
      uint32_t length;
      if (!getString(provider, readU32(record), &value, &length) ||
          !getString(provider, readU32(record + 4), &value, &length) ||
          record[8] > 1u)
      {
         *error = "packed reference record is invalid";
         return 0;
      }
   }

   for (i = 0; i < provider->externalReferenceCount; ++i)
   {
      const uint8_t* external = externalReferenceRecord(provider, i);
      uint32_t sourceIndex = readU32(external);
      uint32_t referenceIndex = readU32(external + 4);
      const uint8_t* source;
      const uint8_t* reference;
      const uint8_t* target;
      uint32_t targetLength;
      uint32_t targetIndex;
      uint32_t referenceStart;
      uint16_t referenceCount;

      if (sourceIndex >= provider->nodeCount ||
          referenceIndex >= provider->referenceCount)
      {
         *error = "packed external reference index is invalid";
         return 0;
      }

      source = nodeRecord(provider, sourceIndex);
      referenceStart = readU32(source + 8);
      referenceCount = readU16(source + 14);
      if (referenceIndex < referenceStart ||
          referenceIndex >= referenceStart + referenceCount)
      {
         *error = "packed external reference source is invalid";
         return 0;
      }

      reference = referenceRecord(provider, referenceIndex);
      getString(
         provider, readU32(reference + 4), &target, &targetLength);
      if (findNode(
            provider, (const char*)target, targetLength, &targetIndex))
      {
         *error = "packed external reference target is internal";
         return 0;
      }
   }

   for (i = 0; i < provider->fieldCount; ++i)
   {
      const uint8_t* record = fieldRecord(provider, i);
      const uint8_t* value;
      const uint8_t* cursor;
      uint32_t length;
      uint32_t offset = readU32(record + 4);
      if (!getString(provider, readU32(record), &value, &length) ||
          offset < provider->valueOffset ||
          offset >= provider->valueOffset + provider->valueSize)
      {
         *error = "packed field record is invalid";
         return 0;
      }
      cursor = provider->data + offset;
      if (!skipValue(provider, &cursor, 0))
      {
         *error = "packed field value is invalid";
         return 0;
      }
   }
   return 1;
}

static PackedProvider* checkProvider(lua_State* L, int index)
{
   return (PackedProvider*)luaL_checkudata(L, index, PROVIDER_MT);
}

static PackedView* checkView(lua_State* L, int index, const char* name)
{
   return (PackedView*)luaL_checkudata(L, index, name);
}

static int absoluteIndex(lua_State* L, int index)
{
   if (index > 0 || index <= LUA_REGISTRYINDEX)
      return index;
   return lua_gettop(L) + index + 1;
}

static void retainOwner(lua_State* L, int ownerIndex, int valueIndex)
{
   ownerIndex = absoluteIndex(L, ownerIndex);
   valueIndex = absoluteIndex(L, valueIndex);
   lua_pushvalue(L, ownerIndex);
   lua_setuservalue(L, valueIndex);
}

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
         getString(provider, readU32(p), &value, &length);
         p += 4;
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
      const uint8_t* record = nodeRecord(provider, middle);
      const uint8_t* candidate;
      uint32_t candidateLength;
      int comparison;
      getString(
         provider, readU32(record), &candidate, &candidateLength);
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

static int findAttribute(
   const PackedProvider* provider,
   uint32_t nodeIndex,
   uint16_t attributeId,
   const uint8_t** result)
{
   const uint8_t* node = nodeRecord(provider, nodeIndex);
   uint32_t start = readU32(node + 4);
   uint16_t count = readU16(node + 12);
   uint32_t first = 0;
   uint32_t last = count;
   while (first < last)
   {
      uint32_t middle = first + (last - first) / 2;
      const uint8_t* record = attributeRecord(provider, start + middle);
      uint16_t candidate = readU16(record);
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

static int pushAttribute(
   lua_State* L,
   const PackedProvider* provider,
   uint32_t nodeIndex,
   uint16_t attributeId)
{
   const uint8_t* record;
   const uint8_t* cursor;
   if (!findAttribute(provider, nodeIndex, attributeId, &record))
      return 0;
   cursor = provider->data + readU32(record + 4);
   decodeValue(L, provider, &cursor, 0);
   return 1;
}

static int pushReference(
   lua_State* L,
   const PackedProvider* provider,
   uint32_t index)
{
   const uint8_t* record = referenceRecord(provider, index);
   const uint8_t* value;
   uint32_t length;
   lua_createtable(L, 0, 3);

   getString(provider, readU32(record), &value, &length);
   lua_pushlstring(L, (const char*)value, length);
   lua_setfield(L, -2, "type");

   getString(provider, readU32(record + 4), &value, &length);
   lua_pushlstring(L, (const char*)value, length);
   lua_setfield(L, -2, "target");

   lua_pushboolean(L, record[8] != 0);
   lua_setfield(L, -2, "isForward");
   return 1;
}

static int pushView(
   lua_State* L,
   PackedProvider* provider,
   uint32_t nodeIndex,
   const char* metatable,
   int ownerIndex)
{
   PackedView* view = (PackedView*)lua_newuserdata(L, sizeof(PackedView));
   view->provider = provider;
   view->nodeIndex = nodeIndex;
   luaL_setmetatable(L, metatable);
   retainOwner(L, ownerIndex, -1);
   return 1;
}

static int pushNode(
   lua_State* L,
   PackedProvider* provider,
   uint32_t nodeIndex,
   int ownerIndex)
{
   return pushView(L, provider, nodeIndex, NODE_MT, ownerIndex);
}

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

static int providerNodesIterator(lua_State* L)
{
   PackedProvider* provider =
      checkProvider(L, lua_upvalueindex(1));
   uint32_t* position =
      (uint32_t*)lua_touserdata(L, lua_upvalueindex(2));
   const uint8_t* record;
   const uint8_t* nodeId;
   uint32_t nodeIdLength;
   uint32_t index;

   if (*position >= provider->nodeCount)
      return 0;
   index = (*position)++;
   record = nodeRecord(provider, index);
   getString(provider, readU32(record), &nodeId, &nodeIdLength);
   lua_pushlstring(L, (const char*)nodeId, nodeIdLength);
   pushNode(L, provider, index, lua_upvalueindex(1));
   return 2;
}

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

static int providerStats(lua_State* L)
{
   PackedProvider* provider = checkProvider(L, 1);
   lua_createtable(L, 0, 7);
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
#undef SET_STAT
   return 1;
}

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

   if (*position >= provider->externalReferenceCount)
      return 0;

   external = externalReferenceRecord(provider, (*position)++);
   source = nodeRecord(provider, readU32(external));
   getString(provider, readU32(source), &sourceId, &sourceIdLength);
   lua_pushlstring(L, (const char*)sourceId, sourceIdLength);
   pushReference(L, provider, readU32(external + 4));
   return 2;
}

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

static int providerIndex(lua_State* L)
{
   const char* key = luaL_checkstring(L, 2);
   if (strcmp(key, "getNode") == 0)
      lua_pushcfunction(L, providerGetNode);
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

static int providerPairs(lua_State* L)
{
   return providerIterateNodes(L);
}

static int attrsIndex(lua_State* L)
{
   PackedView* view = checkView(L, 1, ATTRS_MT);
   int attributeId;
   if (lua_type(L, 2) == LUA_TNUMBER)
      attributeId = (int)luaL_checkinteger(L, 2);
   else
      attributeId = attributeNameToId(luaL_checkstring(L, 2));
   if (attributeId <= 0 || attributeId > UINT16_MAX ||
       !pushAttribute(
          L, view->provider, view->nodeIndex, (uint16_t)attributeId))
      lua_pushnil(L);
   return 1;
}

static int attrsIterator(lua_State* L)
{
   PackedView* view = checkView(L, lua_upvalueindex(1), ATTRS_MT);
   uint32_t* position =
      (uint32_t*)lua_touserdata(L, lua_upvalueindex(2));
   const uint8_t* node = nodeRecord(view->provider, view->nodeIndex);
   uint32_t start = readU32(node + 4);
   uint16_t count = readU16(node + 12);
   const uint8_t* record;
   const uint8_t* cursor;

   if (*position >= count)
      return 0;
   record = attributeRecord(view->provider, start + (*position)++);
   lua_pushinteger(L, readU16(record));
   cursor = view->provider->data + readU32(record + 4);
   decodeValue(L, view->provider, &cursor, 0);
   return 2;
}

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

static int refsLength(lua_State* L)
{
   PackedView* view = checkView(L, 1, REFS_MT);
   const uint8_t* node = nodeRecord(view->provider, view->nodeIndex);
   lua_pushinteger(L, readU16(node + 14));
   return 1;
}

static int refsIndex(lua_State* L)
{
   PackedView* view = checkView(L, 1, REFS_MT);
   lua_Integer requested = luaL_checkinteger(L, 2);
   const uint8_t* node = nodeRecord(view->provider, view->nodeIndex);
   uint32_t start = readU32(node + 8);
   uint16_t count = readU16(node + 14);
   if (requested < 1 || (uint64_t)requested > count)
   {
      lua_pushnil(L);
      return 1;
   }
   return pushReference(
      L, view->provider, start + (uint32_t)requested - 1u);
}

static int refsIterator(lua_State* L)
{
   PackedView* view = checkView(L, lua_upvalueindex(1), REFS_MT);
   uint32_t* position =
      (uint32_t*)lua_touserdata(L, lua_upvalueindex(2));
   const uint8_t* node = nodeRecord(view->provider, view->nodeIndex);
   uint32_t start = readU32(node + 8);
   uint16_t count = readU16(node + 14);
   if (*position >= count)
      return 0;
   lua_pushinteger(L, (lua_Integer)*position + 1);
   pushReference(L, view->provider, start + (*position)++);
   return 2;
}

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

static int nodeGetAttribute(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   int attributeId;
   if (lua_type(L, 2) == LUA_TNUMBER)
      attributeId = (int)luaL_checkinteger(L, 2);
   else
      attributeId = attributeNameToId(luaL_checkstring(L, 2));
   if (attributeId <= 0 || attributeId > UINT16_MAX)
   {
      lua_pushboolean(L, 0);
      lua_pushnil(L);
      return 2;
   }
   lua_pushboolean(L, 1);
   if (!pushAttribute(
          L, view->provider, view->nodeIndex, (uint16_t)attributeId))
   {
      lua_pop(L, 1);
      lua_pushboolean(L, 0);
      lua_pushnil(L);
   }
   return 2;
}

static int nodeIterateAttributes(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   pushView(L, view->provider, view->nodeIndex, ATTRS_MT, 1);
   lua_replace(L, 1);
   lua_settop(L, 1);
   return attrsPairs(L);
}

static int nodeIterateReferences(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   pushView(L, view->provider, view->nodeIndex, REFS_MT, 1);
   lua_replace(L, 1);
   lua_settop(L, 1);
   return refsPairs(L);
}

static int nodeGetReference(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   size_t typeLength;
   size_t targetLength;
   const char* type = luaL_checklstring(L, 2, &typeLength);
   const char* target = luaL_checklstring(L, 3, &targetLength);
   int isForward = lua_toboolean(L, 4);
   const uint8_t* node = nodeRecord(view->provider, view->nodeIndex);
   uint32_t start = readU32(node + 8);
   uint16_t count = readU16(node + 14);
   uint16_t i;
   for (i = 0; i < count; ++i)
   {
      const uint8_t* record = referenceRecord(view->provider, start + i);
      const uint8_t* candidateType;
      const uint8_t* candidateTarget;
      uint32_t candidateTypeLength;
      uint32_t candidateTargetLength;
      getString(
         view->provider, readU32(record),
         &candidateType, &candidateTypeLength);
      getString(
         view->provider, readU32(record + 4),
         &candidateTarget, &candidateTargetLength);
      if (compareBytes(
             (const uint8_t*)type, typeLength,
             candidateType, candidateTypeLength) == 0 &&
          compareBytes(
             (const uint8_t*)target, targetLength,
             candidateTarget, candidateTargetLength) == 0 &&
          (record[8] != 0) == isForward)
      {
         lua_pushboolean(L, 1);
         pushReference(L, view->provider, start + i);
         return 2;
      }
   }
   lua_pushboolean(L, 0);
   lua_pushnil(L);
   return 2;
}

static int findField(
   const PackedView* view,
   const char* key,
   size_t keyLength,
   const uint8_t** result)
{
   const uint8_t* node = nodeRecord(view->provider, view->nodeIndex);
   uint32_t start = readU32(node + 16);
   uint16_t count = readU16(node + 20);
   uint16_t i;
   for (i = 0; i < count; ++i)
   {
      const uint8_t* record = fieldRecord(view->provider, start + i);
      const uint8_t* candidate;
      uint32_t candidateLength;
      getString(
         view->provider, readU32(record), &candidate, &candidateLength);
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

static int pushField(lua_State* L, const PackedView* view, const char* key)
{
   const uint8_t* record;
   const uint8_t* cursor;
   if (!findField(view, key, strlen(key), &record))
      return 0;
   cursor = view->provider->data + readU32(record + 4);
   decodeValue(L, view->provider, &cursor, 0);
   return 1;
}

static int nodeGetDefinition(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   if (!pushAttribute(L, view->provider, view->nodeIndex, 23u))
      lua_pushnil(L);
   return 1;
}

static int nodeGetCodecKind(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   if (!pushField(L, view, "CodecKind"))
      lua_pushnil(L);
   return 1;
}

static int nodeGetDataTypeNodeId(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   if (!pushField(L, view, "DataTypeId") &&
       !pushAttribute(L, view->provider, view->nodeIndex, 1u))
      lua_pushnil(L);
   return 1;
}

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

static int nodeIndex(lua_State* L)
{
   PackedView* view = checkView(L, 1, NODE_MT);
   size_t keyLength;
   const char* key = luaL_checklstring(L, 2, &keyLength);

   if (strcmp(key, "Attrs") == 0)
      return pushView(L, view->provider, view->nodeIndex, ATTRS_MT, 1);
   if (strcmp(key, "Refs") == 0)
      return pushView(L, view->provider, view->nodeIndex, REFS_MT, 1);
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
   else if (strcmp(key, "getCodecKind") == 0)
      lua_pushcfunction(L, nodeGetCodecKind);
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
      cursor = view->provider->data + readU32(record + 4);
      decodeValue(L, view->provider, &cursor, 0);
   }
   return 1;
}

static int nodePairsIterator(lua_State* L)
{
   PackedView* view = checkView(L, lua_upvalueindex(1), NODE_MT);
   uint32_t* position =
      (uint32_t*)lua_touserdata(L, lua_upvalueindex(2));
   const uint8_t* node = nodeRecord(view->provider, view->nodeIndex);
   uint32_t start = readU32(node + 16);
   uint16_t count = readU16(node + 20);

   if (*position == 0)
   {
      ++(*position);
      lua_pushliteral(L, "Attrs");
      pushView(
         L, view->provider, view->nodeIndex,
         ATTRS_MT, lua_upvalueindex(1));
      return 2;
   }
   if (*position == 1)
   {
      ++(*position);
      lua_pushliteral(L, "Refs");
      pushView(
         L, view->provider, view->nodeIndex,
         REFS_MT, lua_upvalueindex(1));
      return 2;
   }
   if (*position - 2u < count)
   {
      const uint8_t* record =
         fieldRecord(view->provider, start + *position - 2u);
      const uint8_t* key;
      const uint8_t* cursor;
      uint32_t keyLength;
      ++(*position);
      getString(
         view->provider, readU32(record), &key, &keyLength);
      lua_pushlstring(L, (const char*)key, keyLength);
      cursor = view->provider->data + readU32(record + 4);
      decodeValue(L, view->provider, &cursor, 0);
      return 2;
   }
   return 0;
}

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

   if (!validateProvider(provider, &error))
      return luaL_error(L, "cannot mount packed address space: %s", error);

   luaL_setmetatable(L, PROVIDER_MT);
   retainOwner(L, 1, -1);
   return 1;
}

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
   if (!validateProvider(provider, &error))
      return luaL_error(
         L, "cannot mount built-in packed address space: %s", error);
   luaL_setmetatable(L, PROVIDER_MT);
   return 1;
}

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

int luaopen_opcua_packed(lua_State* L)
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

void luaopen_opcua_packed_static(lua_State* L)
{
   luaL_requiref(L, "opcua_packed", luaopen_opcua_packed, 1);
   lua_pop(L, 1);
}
