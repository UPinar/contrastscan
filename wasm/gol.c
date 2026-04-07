#include "gol.h"
#include <stdlib.h>   // malloc, free, rand, srand
#include <math.h>     // sqrt, atan2, fmod, cos
#include <stdint.h>
#include <time.h>     // time (for srand seed)

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#define EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define EXPORT
#endif

#define PI 3.14159265358979323846
#define SPAWN_RADIUS 60
#define MAX_CELL_BUFFER 65536
#define BOUNDS_LIMIT 10000
#define TOMBSTONE ((Cell_t*)(uintptr_t)1)

// --- Color gradient (site theme) ---
// Age 0-30:  green (#22c55e) → blue (#3b82f6)
// Age 30-60: blue (#3b82f6) → purple (#8b5cf6)
// Age 60+:   cap at purple
static Color_t GetCellColor(uint32_t age)
{
  if (age > 60) age = 60;
  uint8_t r, g, b;
  if (age < 30)
  {
    float t = age / 30.0f;
    r = (uint8_t)(34  + t * 25);
    g = (uint8_t)(197 - t * 67);
    b = (uint8_t)(94  + t * 152);
  }
  else
  {
    float t = (age - 30) / 30.0f;
    r = (uint8_t)(59  + t * 80);
    g = (uint8_t)(130 - t * 38);
    b = 246;
  }
  return (Color_t){r, g, b};
}

// --- Point-in-polygon test (edge-distance, matches GameOfLife repo) ---
static int IsInsidePolygon(int32_t x, int32_t y,
                           int32_t sides, int32_t radius, double rotation)
{
  double angle = atan2(y, x) - rotation;
  double dist = sqrt((double)(x * x + y * y));
  double sectorAngle = 2.0 * PI / sides;
  angle = fmod(angle + 10.0 * PI, sectorAngle);
  double edgeDist = radius * cos(PI / sides) / cos(angle - PI / sides);
  return dist <= edgeDist;
}

// --- Create polygon shape and populate ALL cells inside ---
static void CreatePolygon(HashTable_t* p_hashTable,
                          int32_t cx, int32_t cy,
                          int32_t sides, double rotation)
{
  if (sides < 3) return;
  if (sides > 120) sides = 120;
  int32_t radius = SPAWN_RADIUS;

  for (int32_t y = -radius; y <= radius; ++y)
  {
    for (int32_t x = -radius; x <= radius; ++x)
    {
      if (IsInsidePolygon(x, y, sides, radius, rotation))
      {
        Cell_t* cell = (Cell_t*)malloc(sizeof(Cell_t));
        if (!cell) continue;
        cell->m_x = cx + x;
        cell->m_y = cy + y;
        cell->m_age = 0;
        HashTable_InsertCell(p_hashTable, cell);
      }
    }
  }
}

// --- Game of Life step (exact copy from GameOfLife repo) ---
static void UpdateNextFrameCells(HashTable_t** pp_hashTable)
{
  HashTable_t* p_oldHashTable = *pp_hashTable;
  HashTable_t* p_newHashTable = HashTable_Create(p_oldHashTable->m_capacity);
  if (!p_newHashTable) return;

  Cell_t* p_currentCell;
  int32_t candidateX, candidateY;
  uint8_t liveNeighbors;

  for (size_t i = 0; i < p_oldHashTable->m_capacity; ++i)
  {
    p_currentCell = p_oldHashTable->m_cellArray[i];
    if (!p_currentCell || p_currentCell == TOMBSTONE) continue;

    for (int dx = -1; dx <= 1; ++dx)
    {
      for (int dy = -1; dy <= 1; ++dy)
      {
        candidateX = p_currentCell->m_x + dx;
        candidateY = p_currentCell->m_y + dy;

        liveNeighbors = 0;
        for (int ddx = -1; ddx <= 1; ++ddx)
        {
          for (int ddy = -1; ddy <= 1; ++ddy)
          {
            if (ddx == 0 && ddy == 0) continue;
            Cell_t neighborProbe = { .m_x = candidateX + ddx, .m_y = candidateY + ddy, .m_age = 0 };
            if (HashTable_FindCell(p_oldHashTable, &neighborProbe))
              liveNeighbors++;
          }
        }

        Cell_t* p_existingCell = HashTable_FindCell(p_oldHashTable, &(Cell_t){ .m_x = candidateX, .m_y = candidateY, .m_age = 0 });
        int is_cell_alive = p_existingCell != NULL;

        if ((is_cell_alive && (liveNeighbors == 2 || liveNeighbors == 3)) ||
            (!is_cell_alive && liveNeighbors == 3))
        {
          Cell_t* p_newCell = (Cell_t*)malloc(sizeof(Cell_t));
          if (!p_newCell) continue;
          p_newCell->m_x = candidateX;
          p_newCell->m_y = candidateY;
          p_newCell->m_age = is_cell_alive ? p_existingCell->m_age + 1 : 0;
          HashTable_InsertCell(p_newHashTable, p_newCell);
        }
      }
    }
  }

  HashTable_Destroy(p_oldHashTable);
  *pp_hashTable = p_newHashTable;
}

// --- Static state ---
static HashTable_t* g_hashTable   = NULL;
static int32_t*     g_cellBuffer  = NULL;   // flat export buffer [x,y,age, ...]
static uint32_t     g_cellCount   = 0;
static size_t       g_prevSize    = 0;
static uint8_t      g_staleFrames = 0;
static int          g_initialized = 0;
static int32_t      g_minX = -200, g_minY = -200;
static int32_t      g_maxX =  200, g_maxY =  200;

// Track spawn points with their pattern
#define MAX_SPAWNS 4
static struct { int32_t cx, cy, sides; double rotation; } g_spawnPoints[MAX_SPAWNS];
static int g_spawnCount = 0;

// --- WASM Exports ---

EXPORT void gol_init(int32_t cx, int32_t cy, int32_t sides, double rotation)
{
  if (g_hashTable) HashTable_Destroy(g_hashTable);
  if (g_cellBuffer) free(g_cellBuffer);

  srand((unsigned)time(NULL));
  g_hashTable = HashTable_Create(1 << 14);  // 16384 initial
  if (!g_hashTable) return;

  g_cellBuffer = (int32_t*)malloc(MAX_CELL_BUFFER * 3 * sizeof(int32_t));
  if (!g_cellBuffer) { HashTable_Destroy(g_hashTable); g_hashTable = NULL; return; }

  CreatePolygon(g_hashTable, cx, cy, sides, rotation);
  g_spawnCount = 1;
  g_spawnPoints[0].cx = cx; g_spawnPoints[0].cy = cy;
  g_spawnPoints[0].sides = sides; g_spawnPoints[0].rotation = rotation;
  g_cellCount    = 0;
  g_prevSize     = 0;
  g_staleFrames  = 0;
  g_initialized  = 1;
  g_minX = -200; g_minY = -200;
  g_maxX = 200;  g_maxY = 200;
}

EXPORT uint32_t gol_step(void)
{
  if (!g_initialized || !g_hashTable) return 0;

  UpdateNextFrameCells(&g_hashTable);

  // Auto-repeat: stable/oscillating for 10+ frames → clear + respawn new pattern
  size_t currentSize = g_hashTable->m_size;
  size_t diff = currentSize > g_prevSize
    ? currentSize - g_prevSize
    : g_prevSize - currentSize;

  if (diff <= 50)
    g_staleFrames++;
  else
    g_staleFrames = 0;
  g_prevSize = currentSize;

  if (g_staleFrames >= 10)
  {
    for (int i = 0; i < g_spawnCount; i++)
      CreatePolygon(g_hashTable, g_spawnPoints[i].cx, g_spawnPoints[i].cy,
                    g_spawnPoints[i].sides, g_spawnPoints[i].rotation);
    g_staleFrames = 0;
    g_prevSize = g_hashTable->m_size;
  }

  // Fill export buffer
  g_cellCount = 0;
  for (size_t i = 0; i < g_hashTable->m_capacity && g_cellCount < MAX_CELL_BUFFER; ++i)
  {
    Cell_t* c = g_hashTable->m_cellArray[i];
    if (c && c != TOMBSTONE &&
        c->m_x >= g_minX && c->m_x <= g_maxX &&
        c->m_y >= g_minY && c->m_y <= g_maxY)
    {
      size_t off = g_cellCount * 3;
      g_cellBuffer[off]     = c->m_x;
      g_cellBuffer[off + 1] = c->m_y;
      g_cellBuffer[off + 2] = (int32_t)c->m_age;
      g_cellCount++;
    }
  }

  return g_cellCount;
}

EXPORT int32_t* gol_get_cells(void)
{
  return g_cellBuffer;
}

EXPORT uint32_t gol_cell_count(void)
{
  return g_cellCount;
}

EXPORT void gol_reset(void)
{
  if (g_hashTable) { HashTable_Destroy(g_hashTable); g_hashTable = NULL; }
  if (g_cellBuffer) { free(g_cellBuffer); g_cellBuffer = NULL; }
  g_cellCount   = 0;
  g_prevSize    = 0;
  g_staleFrames = 0;
  g_initialized = 0;
  g_minX = -200; g_minY = -200;
  g_maxX = 200;  g_maxY = 200;
}

EXPORT void gol_spawn(int32_t cx, int32_t cy, int32_t sides, double rotation)
{
  if (!g_initialized || !g_hashTable) return;
  CreatePolygon(g_hashTable, cx, cy, sides, rotation);
  if (g_spawnCount < MAX_SPAWNS)
  {
    g_spawnPoints[g_spawnCount].cx = cx;
    g_spawnPoints[g_spawnCount].cy = cy;
    g_spawnPoints[g_spawnCount].sides = sides;
    g_spawnPoints[g_spawnCount].rotation = rotation;
    g_spawnCount++;
  }
}

EXPORT void gol_set_bounds(int32_t minX, int32_t minY, int32_t maxX, int32_t maxY)
{
  if (minX < -BOUNDS_LIMIT) minX = -BOUNDS_LIMIT;
  if (minY < -BOUNDS_LIMIT) minY = -BOUNDS_LIMIT;
  if (maxX >  BOUNDS_LIMIT) maxX =  BOUNDS_LIMIT;
  if (maxY >  BOUNDS_LIMIT) maxY =  BOUNDS_LIMIT;
  if (minX >= maxX) { minX = -200; maxX = 200; }
  if (minY >= maxY) { minY = -200; maxY = 200; }
  g_minX = minX;
  g_minY = minY;
  g_maxX = maxX;
  g_maxY = maxY;
}
