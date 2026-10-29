extern "C" bool FindLuaState(void);

extern "C" void ExecuteLuauBytecode(const char* source, size_t size) {
    if (!g_live_L) {
        SporkLog(@"L is NULL. Trying to find it...");
        FindLuaState();
    }
    
    if (!g_live_L) {
        SporkLog(@"L is NULL. Wait for game.");
        return;
    }
    
    uintptr_t base = get_robloxlib_base();
    if (!base) {
        SporkLog(@"RobloxLib base is NULL.");
        return;
    }
    
    luau_load_t luau_load = (luau_load_t)(base + OFFSET_LUAU_LOAD);
    lua_pcall_t lua_pcall = (lua_pcall_t)(base + OFFSET_LUA_PCALL);
    lua_newthread_t lua_newthread = (lua_newthread_t)(base + OFFSET_LUA_NEWTHREAD);
    luaL_sandboxthread_t luaL_sandboxthread = (luaL_sandboxthread_t)(base + OFFSET_LUA_SANDBOXTHREAD);
    
    in_hook_exec = 1;
    int sig = sigsetjmp(hook_jump_buffer, 1);
    if (sig == 0) {
        void* new_L = lua_newthread(g_live_L);
        if (new_L) {
            luaL_sandboxthread(new_L);
            
            int status = -1;
            if (OFFSET_LUAU_COMPILE != 0x0) {
                luau_compile_t luau_compile = (luau_compile_t)(base + OFFSET_LUAU_COMPILE);
                size_t bytecode_size = 0;
                char* bytecode = luau_compile(source, size, NULL, &bytecode_size);
                if (bytecode && bytecode_size > 0) {
                    SporkLog(@"Compiled bytecode size: %zu", bytecode_size);
                    status = luau_load(new_L, "SporkScript", bytecode, bytecode_size, 0);
                    free(bytecode);
                } else {
                    SporkLog(@"luau_compile failed.");
                }
            } else {
                SporkLog(@"OFFSET_LUAU_COMPILE missing. Testing pre-compiled...");
                status = luau_load(new_L, "SporkTest", (const char*)test_bytecode, sizeof(test_bytecode), 0);
            }
            
            if (status == 0) {
                lua_pcall(new_L, 0, 0, 0);
                SporkLog(@"Executed successfully!");
            } else {
                SporkLog(@"luau_load failed. Status: %d", status);
            }
        }
        in_hook_exec = 0;
    } else {
        in_hook_exec = 0;
        SporkLog(@"CRASH CAUGHT: Signal %d", sig);
    }
}
