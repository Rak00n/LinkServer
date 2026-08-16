# LinkServer

Server for Link SDN Platform.

## Network Performance Fixes Applied

### 1. Thread Safety (Critical)
- Added `sync.RWMutex` to protect the shared `activeNetworks` map from concurrent read/write races
- Endpoint registration (`upsertEndpoint`) now acquires a write lock
- Network lookups (`forwardPacket`) use read locks for concurrent access

### 2. Memory Leak Prevention
- Added `cleanupStaleEndpoints()` goroutine that runs every 60 seconds
- Endpoints not seen within 90 seconds are automatically evicted
- Empty networks are automatically removed from the map
- Max endpoint limit per network (10,000) with oldest-first eviction

### 3. Proper JSON Handling
- Replaced fragile string concatenation with `json.Marshal()` for building response payloads
- This prevents breaking on special characters (quotes, backslashes, newlines) in payloads
- Proper error handling for JSON marshaling/unmarshaling

### 4. Correct UDP Connection Handling
- Removed dangerous pattern of storing `*net.UDPConn` pointers in endpoint structs (shared connection across goroutines)
- All writes now go through the global `udpServer` variable
- Proper error handling on all `WriteToUDP` calls

### 5. Graceful Shutdown
- Added OS signal handling (SIGINT/SIGTERM) for clean shutdown
- UDP server is properly closed on exit

### 6. Logging Improvements
- Replaced `fmt.Println` with structured `log.Printf` calls
- Proper error/warning levels for debugging

### 7. Configuration Constants
- All magic numbers replaced with named constants
- Easy to tune: `serverPort`, `heartbeatTimeout`, `maxEndpoints`, `cleanupInterval`, `readBufferSize`
