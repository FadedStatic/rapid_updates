/*
 * Copyright 2023 FadedStatic
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <format>

#include "scanner.hpp"


struct addr_match
{
	std::string name;
	std::uintptr_t addr;
};

std::vector<addr_match> get_offs(const process& a)
{
	std::vector<addr_match> return_vector;

	const auto start_time = std::chrono::high_resolution_clock::now();

	const auto reqcheck = util::get_prologue(a, scanner::string_scan(a, "about:blank")[0].loc);
	const auto push_captures = util::get_prologue(a, scanner::string_scan(a, "too many captures")[0].loc);
	const auto push_captures_calls = util::get_calls(a, push_captures);
	const auto luaL_error = push_captures_calls[2].loc;
	const auto luaL_error_calls = util::get_calls(a, luaL_error);
	const auto str_find_aux = util::get_prologue(a, scanner::xref_scan(a, push_captures)[1].loc);
	const auto luaD_throw = luaL_error_calls[luaL_error_calls.size() - 2].loc;
	const auto lua_exception_ctor = util::get_calls(a, luaD_throw)[0].loc;
	const auto luaL_where = luaL_error_calls[0].loc;
	const auto lua_pushvfstring = luaL_error_calls[1].loc;
	const auto luaC_step = luaL_error_calls[2].loc;
	const auto luaC_step_calls = util::get_calls(a, luaC_step);
	const auto luaV_tostring = luaL_error_calls[3].loc;
	const auto add_value = util::get_prologue(a, scanner::xref_scan(a, push_captures)[2].loc);
	const auto add_value_xrefs = scanner::xref_scan(a, add_value);
	const auto str_gsub = util::get_prologue(a, add_value_xrefs[0].loc);
	const auto str_gsub_calls = util::get_calls(a, str_gsub);
	const auto tag_error = util::get_calls(a, str_gsub)[10].loc;
	const auto lua_typename = scanner::string_scan(a, "no value")[2].loc;
	const auto luaL_typeerrorL = util::get_prologue(a, util::get_calls(a, tag_error)[1].loc);
	const auto luaL_typeerrorL_calls = util::get_calls(a, luaL_typeerrorL);
	const auto currfuncname = luaL_typeerrorL_calls[0].loc;
	const auto luaA_toobject = luaL_typeerrorL_calls[1].loc;
	const auto luaA_toobject_xrefs = scanner::xref_scan(a, luaA_toobject);
	const auto luaL_typename = util::get_prologue(a, luaA_toobject_xrefs[11].loc);
	const auto lua_breakpoint = util::get_prologue(a, luaA_toobject_xrefs[13].loc);
	const auto lua_getcoverage = util::get_prologue(a, luaA_toobject_xrefs[14].loc);
	const auto luaL_where_calls = util::get_calls(a, luaL_where);
	const auto luaO_chunkid = luaL_where_calls[1].loc;
	const auto luaT_objtypename = luaL_typeerrorL_calls[2].loc;
	const auto luaT_objtypename_xrefs = scanner::xref_scan(a, luaT_objtypename);
	const auto luaT_objtypenamestr = util::get_calls(a, luaT_objtypename)[0].loc;
	const auto luaT_objtypenamestr_xrefs = scanner::xref_scan(a, luaT_objtypenamestr);
	const auto luaG_typeerrorL = util::get_prologue(a, luaT_objtypename_xrefs[1].loc);
	const auto luaG_ordererror = util::get_prologue(a, luaT_objtypename_xrefs[5].loc);
	const auto luaG_ordererror_xrefs = scanner::xref_scan(a, luaG_ordererror);
	const auto call_orderTM = util::get_prologue(a, luaG_ordererror_xrefs[8].loc);
	const auto call_orderTM_calls = util::get_calls(a, call_orderTM);
	const auto luaG_runerrorL = util::get_calls(a, luaG_ordererror)[2].loc;
	const auto luaG_runerrorL_calls = util::get_calls(a, luaG_runerrorL);
	const auto pusherror = luaG_runerrorL_calls[1].loc;
	const auto pusherror_calls = util::get_calls(a, pusherror);
	const auto luaO_chunkid_xrefs = scanner::xref_scan(a, luaO_chunkid);
	const auto luau_load_inlined = util::get_prologue(a, luaO_chunkid_xrefs[3].loc);
	const auto getfunc = util::get_prologue(a, luaO_chunkid_xrefs[21].loc);
	const auto getfunc_xrefs = scanner::xref_scan(a, getfunc);
	const auto currentline = pusherror_calls[1].loc;
	const auto currentline_xrefs = scanner::xref_scan(a, currentline);
	const auto luaL_argerrorL = util::get_prologue(a, currentline_xrefs[0].loc);
	const auto luaO_pushfstring = pusherror_calls[2].loc;
	const auto luaO_pushfstring_calls = util::get_calls(a, luaO_pushfstring);
	const auto luaO_pushvfstring = luaO_pushfstring_calls[0].loc;
	const auto luaO_pushvfstring_calls = util::get_calls(a, luaO_pushvfstring);
	const auto luaO_pushvfstring_xrefs = scanner::xref_scan(a, luaO_pushvfstring);
	const auto lua_pushfstringL = util::get_prologue(a, luaO_pushvfstring_xrefs[1].loc);
	const auto lua_pushfstringL_xrefs = scanner::xref_scan(a, lua_pushfstringL);
	const auto auxresume = util::get_prologue(a, lua_pushfstringL_xrefs[9].loc);
	const auto auxresume_calls = util::get_calls(a, auxresume);
	const auto lua_resume = auxresume_calls[3].loc;
	const auto lua_resume_calls = util::get_calls(a, lua_resume);
	const auto resume_error = lua_resume_calls[0].loc;
	const auto lua_xmove = auxresume_calls[4].loc;
	const auto lua_xmove_xrefs = scanner::xref_scan(a, lua_xmove);
	const auto lua_xpush = util::get_prologue(a, util::get_epilogue(a, lua_xmove) + 0x10);
	const auto luaD_rawrunprotected = lua_resume_calls[2].loc;
	const auto luaD_rawrunprotected_xrefs = scanner::xref_scan(a, luaD_rawrunprotected);
	const auto lua_resumeerror = util::get_prologue(a, scanner::xref_scan(a, resume_error)[2].loc);
	const auto lua_resumeerror_calls = util::get_calls(a, lua_resumeerror);
	const auto resume_findhandler = lua_resumeerror_calls[1].loc;
	const auto resume_finish = lua_resumeerror_calls[3].loc;
	const auto seterrorobj = util::get_calls(a, resume_finish)[0].loc;
	const auto seterrorobj_xrefs = scanner::xref_scan(a, seterrorobj);
	const auto seterrorobj_calls = util::get_calls(a, seterrorobj);
	const auto newgcoblock = seterrorobj_calls[2].loc;
	const auto luaB_pcally = util::get_prologue(a, seterrorobj_xrefs[2].loc);
	const auto luaB_pcally_calls = util::get_calls(a, luaB_pcally);
	const auto lua_rawcheckstack = luaB_pcally_calls[4].loc;
	const auto lua_rawcheckstack_xrefs = scanner::xref_scan(a, lua_rawcheckstack);
	const auto db_info = util::get_prologue(a, lua_rawcheckstack_xrefs[0].loc);
	const auto luaB_pcallcont = util::get_prologue(a, lua_rawcheckstack_xrefs[2].loc);
	const auto luaB_xpcallcont = util::get_prologue(a, lua_rawcheckstack_xrefs[4].loc);
	const auto auxresumecont = util::get_prologue(a, lua_rawcheckstack_xrefs[6].loc);
	const auto auxresumecont_xrefs = scanner::xref_scan(a, auxresume);
	const auto luaL_pushresults = str_gsub_calls[9].loc;
	const auto luaL_pushresults_xrefs = scanner::xref_scan(a, luaL_pushresults);
	const auto codepoint = util::get_prologue(a, scanner::string_scan(a, "string slice too long")[0].loc);
	const auto codepoint_calls = util::get_calls(a, codepoint);
	const auto lua_tointegerx = codepoint_calls[3].loc;
	const auto lua_tointegerx_calls = util::get_calls(a, lua_tointegerx);
	const auto pseudo2addr = lua_tointegerx_calls[0].loc;
	const auto lua_tounsignedx = lua_tointegerx_calls[1].loc;
	const auto luaL_checkstack = codepoint_calls[4].loc;
	const auto lua_checkstack = util::get_calls(a, luaL_checkstack)[0].loc;
	const auto utf8_decode = codepoint_calls[5].loc;
	const auto utf8_decode_xrefs = scanner::xref_scan(a, utf8_decode);
	const auto utflen = util::get_prologue(a, utf8_decode_xrefs[0].loc);
	const auto iter_aux = util::get_prologue(a, utf8_decode_xrefs[2].loc);
	const auto db_traceback = util::get_prologue(a, luaL_pushresults_xrefs[0].loc);
	const auto utfchar = util::get_prologue(a, luaL_pushresults_xrefs[1].loc);
	const auto utfchar_calls = util::get_calls(a, utfchar);
	const auto buffutfchar = utfchar_calls[0].loc;
	const auto buffutfchar_calls = util::get_calls(a, buffutfchar);
	const auto luaO_utf8esc = buffutfchar_calls[1].loc;
	const auto str_format = util::get_prologue(a, luaL_pushresults_xrefs[8].loc);
	const auto str_format_calls = util::get_calls(a, str_format);
	const auto luaL_tolstring = str_format_calls[str_format_calls.size() - 5].loc;
	const auto luaL_checklstring = str_format_calls[0].loc;
	const auto luaL_extendbuffer = str_format_calls[1].loc;
	const auto luaL_extendbuffer_calls = util::get_calls(a, luaL_extendbuffer);
	const auto luaM_toobig = luaL_extendbuffer_calls[4].loc;
	const auto newpage = luaL_extendbuffer_calls[1].loc;
	const auto newgcoblock2 = luaL_extendbuffer_calls[0].loc;
	const auto luaL_checknumber = str_format_calls[4].loc;
	const auto lua_clock = luaC_step_calls[0].loc;
	const auto gcstep = luaC_step_calls[3].loc;
	const auto gcstep_calls = util::get_calls(a, gcstep);
	const auto gcstep_xrefs = scanner::xref_scan(a, gcstep);
	const auto luaC_fullgc = util::get_prologue(a, gcstep_xrefs[1].loc);
	const auto luaC_fullgc_calls = util::get_calls(a, luaC_fullgc);
	const auto luaC_fullgc_xrefs = scanner::xref_scan(a, luaC_fullgc);
	const auto lua_gc = util::get_prologue(a, luaC_fullgc_xrefs[1].loc);
	const auto markroot = gcstep_calls[0].loc;
	const auto markroot_calls = util::get_calls(a, markroot);
	const auto propagatemark = gcstep_calls[1].loc;
	const auto propagatemark_calls = util::get_calls(a, propagatemark);
	const auto reallymarkobject = markroot_calls[0].loc;
	const auto finishGcCycleMetrics = luaC_fullgc_calls[2].loc;
	const auto shrinkbuffersfull = luaC_fullgc_calls[6].loc;
	const auto lua_collectgarbage = util::get_prologue(a, luaC_fullgc_xrefs[0].loc);
	const auto resume_handle = util::get_prologue(a, seterrorobj_xrefs[0].loc);
	const auto resume_handle_calls = util::get_calls(a, resume_handle);
	const auto luau_poscall = resume_handle_calls[2].loc;
	const auto luau_poscall_xrefs = scanner::xref_scan(a, luau_poscall);
	const auto resume_continue = util::get_prologue(a, luau_poscall_xrefs[0].loc);
	const auto resume_continue_xrefs = scanner::xref_scan(a, resume_continue);
	const auto resume = util::get_prologue(a, resume_continue_xrefs[1].loc);
	const auto resume_calls = util::get_calls(a, resume);
	const auto luaV_tryfuncTM = resume_calls[0].loc;
	const auto metatable_str_xrefs = scanner::string_scan(a, "__metatable");
	const auto luaB_getmetatable = util::get_prologue(a, metatable_str_xrefs[1].loc);
	const auto luaB_setmetatable = util::get_prologue(a, metatable_str_xrefs[2].loc);
	const auto luaB_setmetatable_calls = util::get_calls(a, luaB_setmetatable);
	const auto luaL_getmetafield = luaB_setmetatable_calls[0].loc;
	const auto luaC_barrierf = luaB_setmetatable_calls[1].loc;
	const auto luaC_barrierf_xrefs = scanner::xref_scan(a, luaC_barrierf);
	const auto lua_replace = util::get_prologue(a, luaC_barrierf_xrefs[7].loc);
	const auto gmatch_aux = util::get_prologue(a, luaC_barrierf_xrefs[11].loc);
	const auto clearupvals = util::get_prologue(a, luaC_barrierf_xrefs[13].loc);
	const auto luau_execute = util::get_prologue(a, luaC_barrierf_xrefs[17].loc);
	const auto luau_execute_singlestep = util::get_prologue(a, luaC_barrierf_xrefs[14].loc);
	const auto tfreeze = metatable_str_xrefs[3].loc;
	const auto tclone = metatable_str_xrefs[4].loc;
	const auto lua_isnumber = util::get_calls(a, util::get_prologue(a, scanner::string_scan(a, "attempt to multiply a Vector2 with an incompatible value type or nil")[0].loc))[4].loc;
	const auto luau_execute_handler = util::get_prologue(a, scanner::xref_scan(a, luau_execute)[0].loc);
	const auto luau_execute_handler_xrefs = scanner::xref_scan(a, luau_execute_handler);
	const auto luaB_getfenv = util::get_prologue(a, getfunc_xrefs[0].loc);
	const auto luaB_getfenv_calls = util::get_calls(a, luaB_getfenv);
	const auto luaB_setfenv = util::get_prologue(a, util::get_epilogue(a, luaB_getfenv) + 0x1);
	const auto luaB_setfenv_calls = util::get_calls(a, luaB_setfenv);
	const auto lua_pushthread = luaB_setfenv_calls[3].loc;
	const auto lua_setsafeenv = luaB_getfenv_calls[2].loc;
	const auto luaO_rawequalObj = call_orderTM_calls[0].loc;
	const auto luai_veceq = util::get_calls(a, luaO_rawequalObj)[0].loc;
	const auto callTMres = call_orderTM_calls[1].loc;
	const auto callTMres_xrefs = scanner::xref_scan(a, callTMres);
	const auto getlocal_pre = util::get_prologue(a, scanner::string_scan(a, "Cannot create enough space in lua stack for bridging value")[4].loc);
	const auto getlocal_pre_calls = util::get_calls(a, getlocal_pre);
	const auto lua_getlocal = getlocal_pre_calls[0].loc;
	const auto lua_setlocal = getlocal_pre_calls[5].loc;
	const auto luaF_getlocal = util::get_calls(a, lua_getlocal)[0].loc;
	const auto coclose = util::get_prologue(a, lua_xmove_xrefs[8].loc);
	const auto coclose_calls = util::get_calls(a, coclose);
	const auto lua_resetthread = coclose_calls[1].loc;
	const auto thread_cancel = util::get_prologue(a, scanner::xref_scan(a, lua_resetthread)[0].loc);
	const auto vector_init = util::get_prologue(a, luaC_barrierf_xrefs[1].loc);
	const auto luaL_newmetatable = util::get_prologue(a, callTMres_xrefs[7].loc);
	const auto luaL_register = util::get_prologue(a, callTMres_xrefs[8].loc);
	const auto luaL_findtable = util::get_calls(a, luaL_register)[0].loc;
	const auto call_binTM = util::get_prologue(a, callTMres_xrefs[48].loc);
	const auto call_binTM_xrefs = scanner::xref_scan(a, call_binTM);
	const auto luaB_error = util::get_prologue(a, call_binTM_xrefs[1].loc);
	const auto luaB_error_calls = util::get_calls(a, luaB_error);
	const auto luaL_optinteger = luaB_error_calls[0].loc;
	const auto lua_isstring = luaB_error_calls[1].loc;
	const auto coresumecont = util::get_prologue(a, auxresumecont_xrefs[0].loc);
	const auto auxwrapcont = util::get_prologue(a, auxresumecont_xrefs[1].loc);
	const auto auxwrapcont_jumps = util::get_jumps(a, auxwrapcont);
	const auto interruptThread = auxwrapcont_jumps[0].loc;
	const auto interruptThread_calls = util::get_calls(a, interruptThread);
	const auto luau_callhook = interruptThread_calls[0].loc;
	const auto luaL_callmeta = util::get_prologue(a, luau_execute_handler_xrefs[2].loc);
	const auto callerrfunc = util::get_prologue(a, luau_execute_handler_xrefs[4].loc);
	const auto luaB_pcallrun = util::get_prologue(a, luau_execute_handler_xrefs[5].loc);
	const auto luaB_xpcallerr = util::get_prologue(a, luau_execute_handler_xrefs[6].loc);
	const auto foreachi = util::get_prologue(a, luau_execute_handler_xrefs[8].loc);
	const auto foreachi_calls = util::get_calls(a, foreachi);
	const auto foreach = util::get_prologue(a, luau_execute_handler_xrefs[9].loc);
	const auto sort_func = util::get_prologue(a, luau_execute_handler_xrefs[10].loc);
	const auto lua_objlen = foreachi_calls[0].loc;
	const auto luaL_newstate = util::get_prologue(a, luaD_rawrunprotected_xrefs[3].loc);
	const auto luaL_newstate_calls = util::get_calls(a, luaL_newstate);

	const auto close_state = luaL_newstate_calls[luaL_newstate_calls.size() - 1].loc;
	const auto close_state_xrefs = scanner::xref_scan(a, close_state);
	const auto lua_close = util::get_prologue(a, close_state_xrefs[1].loc);
	const auto luaB_assert = scanner::string_scan(a, "assertion failed!")[0].loc;
	const auto luaL_optlstring = util::get_calls(a, luaB_assert)[1].loc;
	const auto luaF_newproto = util::get_prologue(a, util::get_epilogue(a, luaO_chunkid) + 0x10);
	const auto getglobalstate = util::get_calls(a, util::get_prologue(a, luaA_toobject_xrefs[0].loc))[15].loc;
	const auto scriptcontext_resume = util::get_prologue(a, scanner::string_scan(a, "$Script", {}, 1)[0].loc);
	const auto spawn = util::get_prologue(a, scanner::string_scan(a, "Spawn function requires 1 argument")[2].loc);
	const auto thread_defer = util::get_prologue(a, scanner::string_scan(a, "Maximum re-entrancy depth (%i) exceeded calling task.defer")[0].loc);

	const auto end_time = std::chrono::high_resolution_clock::now();
	std::printf("Time taken: %lldms\r\n", std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());

	return_vector.push_back({ "reqcheck", reqcheck });
	return_vector.push_back({ "push_captures", push_captures });
	return_vector.push_back({ "luaL_error", luaL_error });
	return_vector.push_back({ "str_find_aux", str_find_aux });
	return_vector.push_back({ "luaD_throw", luaD_throw });
	return_vector.push_back({ "luaL_where", luaL_where });
	return_vector.push_back({ "lua_pushvfstring", lua_pushvfstring });
	return_vector.push_back({ "luaC_step", luaC_step });
	return_vector.push_back({ "luaV_tostring", luaV_tostring });
	return_vector.push_back({ "add_value", add_value });
	return_vector.push_back({ "str_gsub", str_gsub });
	return_vector.push_back({ "tag_error", tag_error });
	return_vector.push_back({ "lua_typename", lua_typename });
	return_vector.push_back({ "luaL_typeerrorL", luaL_typeerrorL });
	return_vector.push_back({ "currfuncname", currfuncname });
	return_vector.push_back({ "luaO_chunkid", luaO_chunkid });
	return_vector.push_back({ "luaT_objtypename", luaT_objtypename });
	return_vector.push_back({ "luaT_objtypenamestr", luaT_objtypenamestr });
	return_vector.push_back({ "luaG_typeerrorL", luaG_typeerrorL });
	return_vector.push_back({ "luaG_ordererror", luaG_ordererror });
	return_vector.push_back({ "luaG_runerrorL", luaG_runerrorL });
	return_vector.push_back({ "pusherror", pusherror });
	return_vector.push_back({ "luau_load_inlined", luau_load_inlined });
	return_vector.push_back({ "getfunc", getfunc });
	return_vector.push_back({ "currentline", currentline });
	return_vector.push_back({ "luaL_argerrorL", luaL_argerrorL });
	return_vector.push_back({ "luaO_pushfstring", luaO_pushfstring });
	return_vector.push_back({ "luaO_pushvfstring", luaO_pushvfstring });
	return_vector.push_back({ "lua_pushfstringL", lua_pushfstringL });
	return_vector.push_back({ "luaL_tolstring", luaL_tolstring });
	return_vector.push_back({ "auxresume", auxresume });
	return_vector.push_back({ "lua_resume", lua_resume });
	return_vector.push_back({ "resume_error", resume_error });
	return_vector.push_back({ "lua_xmove", lua_xmove });
	return_vector.push_back({ "lua_xpush", lua_xpush });
	return_vector.push_back({ "luaD_rawrunprotected", luaD_rawrunprotected });
	return_vector.push_back({ "lua_resumeerror", lua_resumeerror });
	return_vector.push_back({ "resume_finish", resume_finish });
	return_vector.push_back({ "seterrorobj", seterrorobj });
	return_vector.push_back({ "newgcoblock", newgcoblock });
	return_vector.push_back({ "resume_findhandler", resume_findhandler });
	return_vector.push_back({ "luaB_pcally", luaB_pcally });
	return_vector.push_back({ "lua_rawcheckstack", lua_rawcheckstack });
	return_vector.push_back({ "db_info", db_info });
	return_vector.push_back({ "luaB_pcallcont", luaB_pcallcont });
	return_vector.push_back({ "luaB_xpcallcont", luaB_xpcallcont });
	return_vector.push_back({ "auxresumecont", auxresumecont });
	return_vector.push_back({ "luaL_pushresults", luaL_pushresults });
	return_vector.push_back({ "codepoint", codepoint });
	return_vector.push_back({ "lua_tointegerx", lua_tointegerx });
	return_vector.push_back({ "lua_tounsignedx", lua_tounsignedx });
	return_vector.push_back({ "pseudo2addr", pseudo2addr });
	return_vector.push_back({ "luaL_checkstack", luaL_checkstack });
	return_vector.push_back({ "utf8_decode", utf8_decode });
	return_vector.push_back({ "utflen", utflen });
	return_vector.push_back({ "iter_aux", iter_aux });
	return_vector.push_back({ "db_traceback", db_traceback });
	return_vector.push_back({ "utfchar", utfchar });
	return_vector.push_back({ "buffutfchar", buffutfchar });
	return_vector.push_back({ "str_format", str_format });
	return_vector.push_back({ "luaL_checklstring", luaL_checklstring });
	return_vector.push_back({ "luaL_extendbuffer", luaL_extendbuffer });
	return_vector.push_back({ "luaM_toobig", luaM_toobig });
	return_vector.push_back({ "newpage", newpage });
	return_vector.push_back({ "newgcoblock2", newgcoblock2 });
	return_vector.push_back({ "luaL_checknumber", luaL_checknumber });
	return_vector.push_back({ "lua_clock", lua_clock });
	return_vector.push_back({ "gcstep", gcstep });
	return_vector.push_back({ "luaC_fullgc", luaC_fullgc });
	return_vector.push_back({ "markroot", markroot });
	return_vector.push_back({ "propagatemark", propagatemark });
	return_vector.push_back({ "reallymarkobject", reallymarkobject });
	return_vector.push_back({ "finishGcCycleMetrics", finishGcCycleMetrics });
	return_vector.push_back({ "shrinkbuffersfull", shrinkbuffersfull });
	return_vector.push_back({ "lua_collectgarbage", lua_collectgarbage });
	return_vector.push_back({ "resume_handle", resume_handle });
	return_vector.push_back({ "luau_poscall", luau_poscall });
	return_vector.push_back({ "resume_continue", resume_continue });
	return_vector.push_back({ "resume", resume });
	return_vector.push_back({ "lua_exception::lua_exception", lua_exception_ctor });
	return_vector.push_back({ "luaV_tryfuncTM", luaV_tryfuncTM });
	return_vector.push_back({ "luaA_toobject", luaA_toobject });
	return_vector.push_back({ "lua_getcoverage", lua_getcoverage });
	return_vector.push_back({ "lua_breakpoint", lua_breakpoint });
	return_vector.push_back({ "luaL_typename", luaL_typename });
	return_vector.push_back({ "lua_checkstack", lua_checkstack });
	return_vector.push_back({ "luaB_getmetatable", luaB_getmetatable });
	return_vector.push_back({ "luaB_setmetatable", luaB_setmetatable });
	return_vector.push_back({ "tfreeze", tfreeze });
	return_vector.push_back({ "tclone", tclone });
	return_vector.push_back({ "luaL_getmetafield", luaL_getmetafield });
	return_vector.push_back({ "luaC_barrierf", luaC_barrierf });
	return_vector.push_back({ "lua_replace", lua_replace });
	return_vector.push_back({ "gmatch_aux", gmatch_aux });
	return_vector.push_back({ "clearupvals", clearupvals });
	return_vector.push_back({ "luau_execute", luau_execute });
	return_vector.push_back({ "luau_execute_singlestep", luau_execute_singlestep });
	return_vector.push_back({ "lua_isnumber", lua_isnumber });
	return_vector.push_back({ "luau_execute_handler", luau_execute_handler });
	return_vector.push_back({ "luau_callhook", luau_callhook });
	return_vector.push_back({ "luaO_rawequalObj", luaO_rawequalObj });
	return_vector.push_back({ "callTMres", callTMres });
	return_vector.push_back({ "call_orderTM", call_orderTM });
	return_vector.push_back({ "luai_veceq", luai_veceq });
	return_vector.push_back({ "luaB_setfenv", luaB_setfenv });
	return_vector.push_back({ "lua_pushthread", lua_pushthread });
	return_vector.push_back({ "luaB_getfenv", luaB_getfenv });
	return_vector.push_back({ "lua_setsafeenv", lua_setsafeenv });
	return_vector.push_back({ "lua_getlocal", lua_getlocal });
	return_vector.push_back({ "lua_setlocal", lua_setlocal });
	return_vector.push_back({ "luaF_getlocal", luaF_getlocal });
	return_vector.push_back({ "coclose", coclose });
	return_vector.push_back({ "lua_resetthread", lua_resetthread });
	return_vector.push_back({ "thread_cancel", thread_cancel });
	return_vector.push_back({ "lua_pushvector", vector_init });
	return_vector.push_back({ "luaL_newmetatable", luaL_newmetatable });
	return_vector.push_back({ "luaL_register", luaL_register });
	return_vector.push_back({ "call_binTM", call_binTM });
	return_vector.push_back({ "luaB_error", luaB_error });
	return_vector.push_back({ "luaL_optinteger", luaL_optinteger });
	return_vector.push_back({ "lua_isstring", lua_isstring });
	return_vector.push_back({ "auxwrapcont", auxwrapcont });
	return_vector.push_back({ "interruptThread", interruptThread });
	return_vector.push_back({ "coresumecont", coresumecont });
	return_vector.push_back({ "luaL_callmeta", luaL_callmeta });
	return_vector.push_back({ "callerrfunc", callerrfunc });
	return_vector.push_back({ "luaB_pcallrun", luaB_pcallrun });
	return_vector.push_back({ "luaB_xpcallerr", luaB_xpcallerr });
	return_vector.push_back({ "foreachi", foreachi });
	return_vector.push_back({ "foreach", foreach });
	return_vector.push_back({ "sort_func", sort_func });
	return_vector.push_back({ "lua_objlen", lua_objlen });
	return_vector.push_back({ "lua_gc", lua_gc });
	return_vector.push_back({ "luaL_newstate", luaL_newstate });
	return_vector.push_back({ "close_state", close_state });
	return_vector.push_back({ "lua_close", lua_close });
	return_vector.push_back({ "luaO_utf8esc", luaO_utf8esc });
	return_vector.push_back({ "luaB_assert", luaB_assert });
	return_vector.push_back({ "luaL_optlstring", luaL_optlstring });
	return_vector.push_back({ "luaL_findtable", luaL_findtable });
	return_vector.push_back({ "luaF_newproto", luaF_newproto });
	return_vector.push_back({ "getglobalstate", getglobalstate });
	return_vector.push_back({ "scriptcontext_resume", scriptcontext_resume });
	return_vector.push_back({ "spawn", spawn });
	return_vector.push_back({ "thread_defer", thread_defer });
	return return_vector;
}



int main()
{
	const scan_cfg cfg =
	{
		//"ntdll.dll"
	};

	const auto a = process("Windows10Universal.exe");
	for (const auto& [name, addr] : get_offs(a))
	{
		std::printf("MakeName(0x%02llX, \"", util::rebase(a, addr));
		std::cout << name << "\");\r\n";
	}

	/*
	std::vector<std::uintptr_t> already_found;
	// here we check for existing addrs (duplicates), easiest way to check for fuckups lol
	for (const auto& [name, addr] : get_offs(a))
	{
		if (std::find(already_found.begin(), already_found.end(), addr) != std::end(already_found))
			std::printf("Duplicate address: %02llX under name: %s\n", util::rebase(a, addr), name.data());

		already_found.push_back(addr);
	}*/
}