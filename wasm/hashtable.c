#include "gol.h"
#include <stdlib.h>    // malloc(), calloc(), free()
#include <stdint.h>    // uintptr_t

// Exact copy from GameOfLife repo (UPinar/GameOfLife)

#define TOMBSTONE ((Cell_t*)(uintptr_t)1)

HashTable_t* HashTable_Create(size_t capacity)
{
  HashTable_t* p_hashTable = (HashTable_t*)malloc(sizeof(HashTable_t));
  if (!p_hashTable) return NULL;

  p_hashTable->m_cellArray = (Cell_t**)calloc(capacity, sizeof(Cell_t*));
  if (!p_hashTable->m_cellArray)
  {
    free(p_hashTable);
    return NULL;
  }

  p_hashTable->m_size = 0;
  p_hashTable->m_capacity = capacity;

  return p_hashTable;
}

void HashTable_Destroy(HashTable_t* p_hashTable)
{
  if (p_hashTable)
  {
    if (p_hashTable->m_cellArray)
    {
      for (size_t i = 0; i < p_hashTable->m_capacity; ++i)
      {
        if (p_hashTable->m_cellArray[i] != NULL &&
            p_hashTable->m_cellArray[i] != TOMBSTONE)
        {
          free(p_hashTable->m_cellArray[i]);
        }
      }
      free(p_hashTable->m_cellArray);
    }
    free(p_hashTable);
  }
}

static size_t HashTable_GetHashKey(int32_t x, int32_t y, size_t capacity)
{
  size_t hash = ((size_t)x * 73856093) ^ ((size_t)y * 19349663);
  return hash % capacity;
}

static void HashTable_ResizeHashTable(HashTable_t* p_hashTable)
{
  size_t oldCapacity    = p_hashTable->m_capacity;
  size_t newCapacity    = oldCapacity * 2;
  Cell_t** oldCellArray = p_hashTable->m_cellArray;

  Cell_t** newCellArray = (Cell_t**)calloc(newCapacity, sizeof(Cell_t*));
  if (!newCellArray) return;

  p_hashTable->m_cellArray = newCellArray;
  p_hashTable->m_capacity  = newCapacity;
  p_hashTable->m_size      = 0;

  for (size_t i = 0; i < oldCapacity; ++i)
  {
    if (oldCellArray[i] != NULL && oldCellArray[i] != TOMBSTONE)
      HashTable_InsertCell(p_hashTable, oldCellArray[i]);
  }

  free(oldCellArray);
}

void HashTable_InsertCell(HashTable_t* p_hashTable, Cell_t* p_cell)
{
  if (p_hashTable->m_size >= p_hashTable->m_capacity)
    HashTable_ResizeHashTable(p_hashTable);

  if (!p_hashTable->m_cellArray)
    return;

  size_t key = HashTable_GetHashKey(p_cell->m_x, p_cell->m_y, p_hashTable->m_capacity);
  size_t startKey = key;

  size_t firstTombstone = (size_t)-1;

  while (p_hashTable->m_cellArray[key] != NULL)
  {
    if (p_hashTable->m_cellArray[key] == TOMBSTONE)
    {
      if (firstTombstone == (size_t)-1)
        firstTombstone = key;
    }
    else if (p_hashTable->m_cellArray[key]->m_x == p_cell->m_x &&
             p_hashTable->m_cellArray[key]->m_y == p_cell->m_y)
    {
      free(p_hashTable->m_cellArray[key]);
      p_hashTable->m_cellArray[key] = p_cell;
      return;
    }
    key = (key + 1) % p_hashTable->m_capacity;
    if (key == startKey) return;
  }

  if (firstTombstone != (size_t)-1)
    key = firstTombstone;

  p_hashTable->m_cellArray[key] = p_cell;
  p_hashTable->m_size++;
}

Cell_t* HashTable_FindCell(const HashTable_t* p_hashTable, const Cell_t* p_cell)
{
  if (!p_hashTable->m_cellArray || !p_cell)
    return NULL;

  size_t key      = HashTable_GetHashKey(p_cell->m_x, p_cell->m_y, p_hashTable->m_capacity);
  size_t startKey = key;
  while (p_hashTable->m_cellArray[key] != NULL)
  {
    if (p_hashTable->m_cellArray[key] != TOMBSTONE &&
        p_hashTable->m_cellArray[key]->m_x == p_cell->m_x &&
        p_hashTable->m_cellArray[key]->m_y == p_cell->m_y)
    {
      return p_hashTable->m_cellArray[key];
    }
    key = (key + 1) % p_hashTable->m_capacity;

    if (key == startKey)
      break;
  }
  return NULL;
}

void HashTable_DeleteCell(HashTable_t* p_hashTable, const Cell_t* p_cell)
{
  if (!p_hashTable->m_cellArray || !p_cell)
    return;

  size_t key      = HashTable_GetHashKey(p_cell->m_x, p_cell->m_y, p_hashTable->m_capacity);
  size_t startKey = key;
  while (p_hashTable->m_cellArray[key] != NULL)
  {
    if (p_hashTable->m_cellArray[key] != TOMBSTONE &&
        p_hashTable->m_cellArray[key]->m_x == p_cell->m_x &&
        p_hashTable->m_cellArray[key]->m_y == p_cell->m_y)
    {
      free(p_hashTable->m_cellArray[key]);
      p_hashTable->m_cellArray[key] = TOMBSTONE;
      p_hashTable->m_size--;
      return;
    }
    key = (key + 1) % p_hashTable->m_capacity;

    if (key == startKey)
      break;
  }
}

void HashTable_Clear(HashTable_t* p_hashTable)
{
  if (!p_hashTable || !p_hashTable->m_cellArray)
    return;

  for (size_t i = 0; i < p_hashTable->m_capacity; ++i)
  {
    if (p_hashTable->m_cellArray[i] != NULL &&
        p_hashTable->m_cellArray[i] != TOMBSTONE)
    {
      free(p_hashTable->m_cellArray[i]);
    }
    p_hashTable->m_cellArray[i] = NULL;
  }

  p_hashTable->m_size = 0;
}
