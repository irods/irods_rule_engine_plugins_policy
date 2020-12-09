#include "policy_composition_framework_event_handler.hpp"

namespace {
    // clang-format off
    using     json = nlohmann::json;
    namespace eh   = irods::policy_composition::event_handler;
    namespace pc   = irods::policy_composition;
    // clang-format on

    const pc::event_map_type p2e{
        {"coll_create",  "CREATE"},
        {"phy_path_reg", "REGISTER"},
        {"rm_coll",      "REMOVE"}
    };

    auto data_obj_inp_handler(
          const std::string&         _rule_name
        , const pc::arguments_type& _arguments
        , ruleExecInfo_t*            _rei) -> std::tuple<std::string, json>
    {
        auto comm = pc::serialize_rsComm_to_json(_rei->rsComm);
        auto it   = pc::advance_or_throw(_arguments, 2);

        auto inp = boost::any_cast<dataObjInp_t*>(*it);

        if(!getValByKey(&inp->condInput, COLLECTION_KW)) {
            return std::make_tuple(eh::SKIP_POLICY_INVOCATION, json{});
        }

        auto obj = pc::serialize_dataObjInp_to_json(*inp);

        const auto event = [&]() -> const std::string {
            std::string op = pc::pep_to_event(p2e, _rule_name);
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
        , const pc::arguments_type& _arguments
        , ruleExecInfo_t*            _rei) -> eh::handler_return_type
    {
        auto it = pc::advance_or_throw(_arguments, 2);

        const auto inp{boost::any_cast<collInp_t*>(*it)};
        const auto event{pc::pep_to_event(p2e, _rule_name)};

        auto obj = pc::serialize_collInp_to_json(*inp);
        obj["policy_enforcement_point"] = _rule_name;
        obj["event"] = event;
        obj["comm"]  = pc::serialize_rsComm_to_json(_rei->rsComm);

        return std::make_tuple(event, obj);

    } // collection_handler

} // namespace

extern "C"
eh::plugin_pointer_type plugin_factory(const std::string& _pn, const std::string& _ctx)
{
    eh::register_handler("coll_create", eh::interfaces::api, collection_handler);
    eh::register_handler("rm_coll",     eh::interfaces::api, collection_handler);

    eh::register_handler("phy_path_reg", eh::interfaces::api, data_obj_inp_handler);

    return eh::make(_pn, _ctx);
} // plugin_factory
