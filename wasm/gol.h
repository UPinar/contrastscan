#ifndef GOL_H
#define GOL_H

#include <stddef.h>   // size_t
#include <stdint.h>   // int32_t, uint32_t

// --- Cell ---
typedef struct {
  int32_t  m_x;
  int32_t  m_y;
  uint32_t m_age;  // frames alive (0 = newborn)
} Cell_t;

// --- Color (replaces Raylib Color) ---
typedef struct {
  uint8_t r, g, b;
} Color_t;

// --- Hash Table (matches GameOfLife repo — no tombstone counter) ---
typedef struct {
  Cell_t** m_cellArray;
  size_t   m_size;
  size_t   m_capacity;
} HashTable_t;

// Hash table operations
HashTable_t* HashTable_Create(size_t capacity);
void         HashTable_Destroy(HashTable_t* p_hashTable);
void         HashTable_InsertCell(HashTable_t* p_hashTable, Cell_t* p_cell);
Cell_t*      HashTable_FindCell(const HashTable_t* p_hashTable, const Cell_t* p_cell);
void         HashTable_DeleteCell(HashTable_t* p_hashTable, const Cell_t* p_cell);
void         HashTable_Clear(HashTable_t* p_hashTable);

// WASM exports
void     gol_init(int32_t cx, int32_t cy, int32_t sides, double rotation);
uint32_t gol_step(void);
int32_t* gol_get_cells(void);
uint32_t gol_cell_count(void);
void     gol_reset(void);
void     gol_spawn(int32_t cx, int32_t cy, int32_t sides, double rotation);
void     gol_set_bounds(int32_t minX, int32_t minY, int32_t maxX, int32_t maxY);

#endif // GOL_H
