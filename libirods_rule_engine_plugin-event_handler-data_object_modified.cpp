
#include "event_handler.hpp"

#include "fmt/format.h"

/*
#include "policy_engine_utilities.hpp"
#include "irods_re_plugin.hpp"
#include "irods_re_ruleexistshelper.hpp"
#include "irods_plugin_context.hpp"
#include "irods_hierarchy_parser.hpp"
#include "event_handler_utilities.hpp"
#include "rule_engine_plugin_configuration_json.hpp"
#include "rcMisc.h"

#include <boost/any.hpp>

#include "boost/lexical_cast.hpp"
#include "boost/regex.hpp"

#include <typeinfo>
#include <algorithm>

#include "json.hpp"
*/

#include "objDesc.hpp"
#include "physPath.hpp"
#include "bulkDataObjReg.h"

// Persistent L1 File Descriptor Table
extern l1desc_t L1desc[NUM_L1_DESC];

namespace {
    // clang-format off
    using     json = nlohmann::json;
    namespace ie   = irods::event_handler;
    // clang-format on

    const std::map<std::string, std::string> p2e {
        { "bulk_data_obj_put",        "CREATE" },
        { "data_obj_chksum",          "CHECKSUM" },
        { "data_obj_copy",            "COPY" },
        { "data_obj_create_and_stat", "CREATE" },
        { "data_obj_create",          "CREATE" },
        { "data_obj_get",             "GET" },
        { "data_obj_lseek",           "SEEK" },
        { "data_obj_phymv",           "REPLICATION" },
        { "data_obj_put",             "PUT" },
        { "data_obj_rename",          "RENAME" },
        { "data_obj_repl",            "REPLICATION" },
        { "data_obj_trim",            "TRIM" },
        { "data_obj_truncate",        "TRUNCATE" },
        { "data_obj_unlink",          "UNLINK" },
        { "phy_path_reg",             "REGISTER" },
    };

    std::map<uint32_t, json> objects_in_flight{};

    std::string hierarchy_resolution_operation{};

    auto invoke_policy_for_bulk_put(
        ruleExecInfo_t*    _rei,
        const std::string& _rule_name,
        genQueryOut_t&     _attr_arr,
        keyValPair_t&      _cond_input) -> void
    {

        const std::string event{hierarchy_resolution_operation};

        auto comm = ie::serialize_rsComm_to_json(_rei->rsComm);

        auto data_name = getSqlResultByInx(&_attr_arr, COL_DATA_NAME);
        if(!data_name) {
            THROW(UNMATCHED_KEY_OR_INDEX, "missing object path");
        }

        auto offset = getSqlResultByInx(&_attr_arr, OFFSET_INX);
        if(!offset) {
            THROW(UNMATCHED_KEY_OR_INDEX, "missing offset");
        }

        std::vector<int> offset_int{};
        for (int i = 0; i < _attr_arr.rowCnt; ++i) {
            offset_int.push_back(atoi(&offset->value[offset->len * i]));
        }

        dataObjInp_t inp{};
        inp.condInput = _cond_input;
        for(int i = 0; i < _attr_arr.rowCnt; ++i) {
            rstrcpy(
                inp.objPath,
                &data_name->value[data_name->len * i],
                sizeof(inp.objPath));

            inp.dataSize = i==0 ? offset_int[0] : offset_int[i]-offset_int[i-1];

            auto obj = ie::serialize_dataObjInp_to_json(inp);

            obj["policy_enforcement_point"] = _rule_name;
            obj["event"] = event;
            obj["comm"]  = comm;

            auto p2i = ie::configuration->plugin_configuration.at("policies_to_invoke");

            ie::invoke_policies_for_event(_rei, event, _rule_name, p2i, obj);

        } // for i

    } // invoke_policy_for_bulk_put

    auto hierarchy_handler(
          const std::string&        _rule_name
        , const ie::arguments_type& _arguments
        , ruleExecInfo_t*           _rei) -> std::tuple<std::string, json>
    {
        auto it = ie::advance_or_throw(_arguments, 3);
        auto op = boost::any_cast<const std::string*>(*it);
        hierarchy_resolution_operation = *op;

        return std::make_tuple(ie::SKIP_POLICY_INVOCATION, json{});

    } // hierarchy_handler

    auto bulk_put_handler(
          const std::string&        _rule_name
        , const ie::arguments_type& _arguments
        , ruleExecInfo_t*           _rei) -> std::tuple<std::string, json>
    {
        auto it = ie::advance_or_throw(_arguments, 2);

        auto inp = boost::any_cast<bulkOprInp_t*>(*it);
        invoke_policy_for_bulk_put(
              _rei
            , _rule_name
            , inp->attriArray
            , inp->condInput);

        return std::make_tuple(ie::SKIP_POLICY_INVOCATION, json{});

    } // bulk_put_handler

    auto copy_rename_handler(
          const std::string&        _rule_name
        , const ie::arguments_type& _arguments
        , ruleExecInfo_t*           _rei) -> std::tuple<std::string, json>
    {
        auto comm = ie::serialize_rsComm_to_json(_rei->rsComm);
        auto it   = ie::advance_or_throw(_arguments, 2);

        const std::string event = ie::pep_to_event(p2e, _rule_name);

        auto inp = boost::any_cast<dataObjCopyInp_t*>(*it);

        auto p2i = ie::configuration->plugin_configuration.at("policies_to_invoke");

        json src = ie::serialize_dataObjInp_to_json(inp->srcDataObjInp);
        src["policy_enforcement_point"] = _rule_name;
        src["event"] = event;
        src["comm"]  = comm;
        ie::invoke_policies_for_event(_rei, event, _rule_name, p2i, src);

        json dst = ie::serialize_dataObjInp_to_json(inp->destDataObjInp);
        dst["policy_enforcement_point"] = _rule_name;
        dst["event"] = event;
        dst["comm"]  = comm;
        ie::invoke_policies_for_event(_rei, event, _rule_name, p2i, dst);

        return std::make_tuple(ie::SKIP_POLICY_INVOCATION, json{});

    } // copy_rename_handler

    auto seek_handler(
          const std::string&        _rule_name
        , const ie::arguments_type& _arguments
        , ruleExecInfo_t*           _rei) -> std::tuple<std::string, json>
    {
        auto comm = ie::serialize_rsComm_to_json(_rei->rsComm);
        auto it   = ie::advance_or_throw(_arguments, 2);

        auto inp = boost::any_cast<openedDataObjInp_t*>(*it);
        const auto l1_idx = inp->l1descInx;
        auto obj = objects_in_flight[l1_idx];

        const std::string event = [&]() -> const std::string {
            const std::string& op = ie::pep_to_event(p2e, _rule_name);
            return op;
        }();

        obj["policy_enforcement_point"] = _rule_name;
        obj["event"] = event;
        obj["comm"]  = comm;

        return std::make_tuple(event, obj);

    } // seek_handler

    // uses the file descriptor table to track modify operations
    // only add an entry if the object is created or opened for write
    auto create_open_handler(
          const std::string&        _rule_name
        , const ie::arguments_type& _arguments
        , ruleExecInfo_t*           _rei) -> std::tuple<std::string, json>
    {
        auto comm = ie::serialize_rsComm_to_json(_rei->rsComm);
        auto it   = ie::advance_or_throw(_arguments, 2);
        auto inp  = boost::any_cast<dataObjInp_t*>(*it);

        json obj{};
        try {
            int l1_idx{};
            std::tie(l1_idx, obj) = ie::get_index_and_json_from_obj_inp(inp);
            objects_in_flight[l1_idx] = obj;
        }
        catch(const irods::exception& _e) {
            rodsLog(
               LOG_ERROR,
               "irods::get_index_and_resource_from_obj_inp failed for [%s]",
               inp->objPath);
        }

        if(inp->openFlags & O_TRUNC) {
            obj["event"] = "TRUNCATE";
            return std::make_tuple(std::string{"TRUNCATE"}, obj);
        }

        return std::make_tuple(ie::SKIP_POLICY_INVOCATION, json{});

    } // create_open_handler

    // uses the tracked file descriptor table operations to invoke policy
    // if changes were actually made to the object
    auto close_handler(
          const std::string&        _rule_name
        , const ie::arguments_type& _arguments
        , ruleExecInfo_t*           _rei) -> std::tuple<std::string, json>
    {
        auto comm = ie::serialize_rsComm_to_json(_rei->rsComm);
        auto it   = ie::advance_or_throw(_arguments, 2);

        uint32_t l1_idx{};
        if(_rule_name.find("replica_close") != std::string::npos) {
            auto bb  = boost::any_cast<bytesBuf_t*>(*it);
            auto tmp = std::string{static_cast<char*>(bb->buf), static_cast<char*>(bb->buf)+bb->len};
            auto obj = json::parse(tmp);
            l1_idx = obj["fd"].get<uint32_t>();
        }
        else {
            const auto inp = boost::any_cast<openedDataObjInp_t*>(*it);
            l1_idx = inp->l1descInx;
        }

        auto obj = objects_in_flight[l1_idx];

        auto open_flags  = boost::lexical_cast<int>(obj["open_flags"].get<std::string>());
        auto write_flag  = (open_flags & O_WRONLY || open_flags & O_RDWR);
        auto create_flag = (open_flags & O_CREAT);

        const auto event = [&]() -> const std::string {
            if("CREATE" == hierarchy_resolution_operation) return "PUT";
            else if("OPEN" == hierarchy_resolution_operation && write_flag) return "WRITE";
            else if("OPEN" == hierarchy_resolution_operation && !write_flag) return "GET";
            else return hierarchy_resolution_operation;
        }();

        obj["policy_enforcement_point"] = _rule_name;
        obj["event"] = event;
        obj["comm"]  = comm;

        return std::make_tuple(event, obj);

    } // close_handler

    auto data_obj_inp_handler(
          const std::string&        _rule_name
        , const ie::arguments_type& _arguments
        , ruleExecInfo_t*           _rei) -> std::tuple<std::string, json>
    {
        auto comm = ie::serialize_rsComm_to_json(_rei->rsComm);
        auto it   = ie::advance_or_throw(_arguments, 2);

        auto inp = boost::any_cast<dataObjInp_t*>(*it);
        auto obj = ie::serialize_dataObjInp_to_json(*inp);

        const auto event = [&]() -> const std::string {
            std::string op = ie::pep_to_event(p2e, _rule_name);
            if(inp->oprType == UNREG_OPR) { return "UNREGISTER"; }
            return op;
        }();

        obj["policy_enforcement_point"] = _rule_name;
        obj["event"] = event;
        obj["comm"]  = comm;

        return std::make_tuple(event, obj);

    } // data_obj_inp_handler

} // namespace

extern "C"
ie::plugin_pointer_type plugin_factory(const std::string& _pn, const std::string& _ctx)
{
    ie::register_handler("data_obj_put",      ie::interfaces::api, data_obj_inp_handler);
    ie::register_handler("data_obj_get",      ie::interfaces::api, data_obj_inp_handler);
    ie::register_handler("data_obj_unlink",   ie::interfaces::api, data_obj_inp_handler);
    ie::register_handler("data_obj_repl",     ie::interfaces::api, data_obj_inp_handler);
    ie::register_handler("phy_path_reg",      ie::interfaces::api, data_obj_inp_handler);
    ie::register_handler("data_obj_truncate", ie::interfaces::api, data_obj_inp_handler);
    ie::register_handler("data_obj_trim",     ie::interfaces::api, data_obj_inp_handler);
    ie::register_handler("data_obj_chksum",   ie::interfaces::api, data_obj_inp_handler);
    ie::register_handler("data_obj_create",   ie::interfaces::api, create_open_handler);
    ie::register_handler("data_obj_open",     ie::interfaces::api, create_open_handler);
    ie::register_handler("data_obj_close",    ie::interfaces::api, close_handler);
    ie::register_handler("replica_open",      ie::interfaces::api, create_open_handler);
    ie::register_handler("replica_close",     ie::interfaces::api, close_handler);
    ie::register_handler("data_obj_lseek",    ie::interfaces::api, seek_handler);
    ie::register_handler("data_obj_rename",   ie::interfaces::api, copy_rename_handler);
    ie::register_handler("data_obj_copy",     ie::interfaces::api, copy_rename_handler);
    ie::register_handler("bulk_data_obj_put", ie::interfaces::api, bulk_put_handler);

    ie::register_handler("resolve_hierarchy", ie::interfaces::resource, hierarchy_handler);

    return ie::make(_pn, _ctx);
} // plugin_factory
