#include "policy_composition_framework_event_handler.hpp"

namespace {
    // clang-format off
    using     json = nlohmann::json;
    namespace ie   = irods::event_handler;
    namespace ipc  = irods::policy_composition;
    // clang-format on

    const ipc::event_map_type p2e{
        {"coll_create",  "CREATE"},
        {"phy_path_reg", "REGISTER"},
        {"rm_coll",      "REMOVE"}
    };

    auto data_obj_inp_handler(
          const std::string&         _rule_name
        , const ipc::arguments_type& _arguments
        , ruleExecInfo_t*            _rei) -> std::tuple<std::string, json>
    {
        auto comm = ipc::serialize_rsComm_to_json(_rei->rsComm);
        auto it   = ipc::advance_or_throw(_arguments, 2);

        auto inp = boost::any_cast<dataObjInp_t*>(*it);

        if(!getValByKey(&inp->condInput, COLLECTION_KW)) {
            return std::make_tuple(ie::SKIP_POLICY_INVOCATION, json{});
        }

        auto obj = ipc::serialize_dataObjInp_to_json(*inp);

        const auto event = [&]() -> const std::string {
            std::string op = ipc::pep_to_event(p2e, _rule_name);
            if(inp->oprType == UNREG_OPR) { return "UNREGISTER"; }
            return op;
        }();

        obj["policy_enforcement_point"] = _rule_name;
        obj["event"] = event;
        obj["comm"]  = comm;

        return std::make_tuple(event, obj);

    } // data_obj_inp_handler

    auto collection_handler(
          const std::string&         _rule_name
        , const ipc::arguments_type& _arguments
        , ruleExecInfo_t*            _rei) -> ie::handler_return_type
    {
        auto it = ipc::advance_or_throw(_arguments, 2);

        const auto inp{boost::any_cast<collInp_t*>(*it)};
        const auto event{ipc::pep_to_event(p2e, _rule_name)};

        auto obj = ipc::serialize_collInp_to_json(*inp);
        obj["policy_enforcement_point"] = _rule_name;
        obj["event"] = event;
        obj["comm"]  = ipc::serialize_rsComm_to_json(_rei->rsComm);

        return std::make_tuple(event, obj);

    } // collection_handler

} // namespace

extern "C"
ie::plugin_pointer_type plugin_factory(const std::string& _pn, const std::string& _ctx)
{
    ie::register_handler("coll_create", ie::interfaces::api, collection_handler);
    ie::register_handler("rm_coll",     ie::interfaces::api, collection_handler);

    ie::register_handler("phy_path_reg", ie::interfaces::api, data_obj_inp_handler);

    return ie::make(_pn, _ctx);
} // plugin_factory
