#include "event_handler.hpp"

#define IRODS_METADATA_ENABLE_SERVER_SIDE_API
#include "metadata.hpp"

namespace {

    // clang-format off
    using     json = nlohmann::json;
    namespace ie   = irods::event_handler;
    namespace ixm  = irods::experimental::metadata;
    // clang-format on

    auto metadata_modified(
          const std::string&        _rule_name
        , const ie::arguments_type& _arguments
        , ruleExecInfo_t*           _rei) -> ie::handler_return_type
    {
        const std::string event{"METADATA"};

        const std::map<ixm::entity_type, std::string> to_variable {
              {ixm::entity_type::collection,  "logical_path"}
            , {ixm::entity_type::data_object, "logical_path"}
            , {ixm::entity_type::user,        "user_name"}
            , {ixm::entity_type::resource,    "source_resource"}
        };

        auto comm = ie::serialize_rsComm_to_json(_rei->rsComm);

        auto it = _arguments.begin();
        std::advance(it, 2);
        if(_arguments.end() == it) {
            THROW(
                SYS_INVALID_INPUT_PARAM,
                "invalid number of arguments");
        }

        const auto inp{boost::any_cast<modAVUMetadataInp_t*>(*it)};
        const auto et{ixm::to_entity_type(inp->arg1)};
        const auto var{to_variable.at(et)};

        json obj{};
        obj["event"] = event;
        obj[var] = inp->arg2;
        obj["metadata"] = {
            {"comm",        comm},
            {"entity_type", ixm::to_entity_string(et)},
            {"operation",   inp->arg0},
            {"entity",      inp->arg2},
            {"attribute",   inp->arg3},
            {"value",       inp->arg4},
            {"units",       inp->arg5}
        };

        obj["policy_enforcement_point"] = _rule_name;

        return std::make_tuple(event, obj);

    } // metadata_modified

} // namespace

extern "C"
ie::plugin_pointer_type plugin_factory(const std::string& _pn, const std::string& _ctx)
{
    ie::register_handler("mod_avu_metadata", ie::interfaces::api, metadata_modified);
    return ie::make(_pn, _ctx);
} // plugin_factory
