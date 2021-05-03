
#include "policy_composition_framework_policy_engine.hpp"
#include "policy_composition_framework_parameter_capture.hpp"

#include "rsModAVUMetadata.hpp"
#include "rsOpenCollection.hpp"
#include "rsReadCollection.hpp"
#include "rsCloseCollection.hpp"

namespace {

    // clang-format off
    namespace pc   = irods::policy_composition;
    namespace pe   = irods::policy_composition::policy_engine;
    using     json = nlohmann::json;
    // clang-format on

    auto update_access_time_for_data_object(
          rsComm_t*          _comm
        , const std::string& _user_name
        , const std::string& _logical_path
        , const std::string& _attribute)
    {
        auto ts = std::to_string(std::time(nullptr));
        modAVUMetadataInp_t avuOp{
            "set",
            "-d",
            const_cast<char*>(_logical_path.c_str()),
            const_cast<char*>(_attribute.c_str()),
            const_cast<char*>(ts.c_str()),
            ""};

        auto mod_fcn = [&](auto& comm) {
            return rsModAVUMetadata(&comm, &avuOp);};

        return pc::exec_as_user(*_comm, _user_name, mod_fcn);

    } // update_access_time_for_data_object

    auto apply_access_time_to_collection(
          rsComm_t*          _comm
        , const std::string& _user_name
        , int                _handle
        , const std::string& _attribute) -> int
    {
        collEnt_t* coll_ent{nullptr};
        auto err = rsReadCollection(_comm, &_handle, &coll_ent);
        while(err >= 0) {
            if(DATA_OBJ_T == coll_ent->objType) {
                using fsp = irods::experimental::filesystem::path;
                auto  lp  = fsp{coll_ent->collName} / fsp{coll_ent->dataName};
                err = update_access_time_for_data_object(_comm, _user_name, lp.string(), _attribute);
                if(err < 0) {
                    rodsLog(LOG_NOTICE,
                            "irods_policy_access_time :: failed to update access time for object [%s]",
                            lp.string().c_str());
                }
            }
            else if(COLL_OBJ_T == coll_ent->objType) {
                collInp_t coll_inp;
                memset(&coll_inp, 0, sizeof(coll_inp));
                rstrcpy(
                    coll_inp.collName,
                    coll_ent->collName,
                    MAX_NAME_LEN);
                auto handle = rsOpenCollection(_comm, &coll_inp);
                err = apply_access_time_to_collection(_comm, _user_name, handle, _attribute);
                rsCloseCollection(_comm, &handle);
            }

            err = rsReadCollection(_comm, &_handle, &coll_ent);

        } // while

        return err;

    } // apply_access_time_to_collection

    auto get_user_name_for_data_object(
        rsComm_t*          comm
      , const std::string& logical_path)
    {
        namespace fs = irods::experimental::filesystem;

        fs::path p{logical_path};

        auto data_name = p.object_name().string();
        auto coll_name = p.parent_path().string();

        auto str = std::string{"SELECT USER_NAME WHERE COLL_NAME = '"}+coll_name+"' AND DATA_NAME = '"+data_name+"'";
        irods::query<rsComm_t> q{comm, str};
        return q.front()[0];

    } // get_user_name_for_data_object



    auto get_user_name_for_collection(
        rsComm_t*          comm
      , const std::string& logical_path)
    {
        auto str = std::string{"SELECT USER_NAME WHERE COLL_NAME = '"}+logical_path+"'";
        irods::query<rsComm_t> q{comm, str};
        return q.front()[0];

    } // get_user_name_for_collection



    auto access_time_policy(const pe::context& ctx, pe::arg_type out)
    {
        auto [user_name, logical_path, source_resource, destination_resource] =
            capture_parameters(ctx.parameters, tag_first_resc);

        pe::client_message({{"0.usage", fmt::format("{} requires user_name, and logical_path", ctx.policy_name)},
                            {"1.user_name", user_name},
                            {"2.logical_path", logical_path}});

        auto comm                 = ctx.rei->rsComm;
        auto attribute            = pc::get(ctx.configuration, "attribute",  std::string{"irods::access_time"});
        auto cond_input           = pc::get(ctx.parameters,    "cond_input", json{});
        auto collection_operation = !cond_input.empty() && !cond_input[COLLECTION_KW].empty();

        if(!collection_operation) {
            user_name = get_user_name_for_data_object(comm, logical_path);

            int status =  update_access_time_for_data_object(comm, user_name, logical_path, attribute);
            if(status < 0) {
                return ERROR(
                           status,
                           boost::format("failed to update access time for object [%s]")
                           % logical_path);
            }
        }
        else {
            user_name = get_user_name_for_collection(comm, logical_path);

            // register a collection
            collInp_t coll_inp;
            memset(&coll_inp, 0, sizeof(coll_inp));
            rstrcpy(
                  coll_inp.collName
                , logical_path.c_str()
                , MAX_NAME_LEN);
            auto handle = rsOpenCollection(comm, &coll_inp);
            if(handle < 0) {
                return ERROR(
                           handle,
                           boost::format("failed to open collection [%s]") %
                           logical_path);
            }

            auto status = apply_access_time_to_collection(comm, user_name, handle, attribute);
            if(status < 0) {
                return ERROR(
                           status,
                           boost::format("failed to update access time for collection [%s]")
                               % logical_path);
            }
        }

        return SUCCESS();

    } // access_time_policy

} // namespace

const char usage[] = R"(
{
    "id": "file:///var/lib/irods/configuration_schemas/v3/policy_engine_usage.json",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": ""
        "input_interfaces": [
            {
                "name" : "event_handler-collection_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-data_object_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-metadata_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-user_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-resource_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "direct_invocation",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "query_results"
                "description" : "",
                "json_schema" : ""
            },
        ],
    "output_json_for_validation" : ""
}
)";

extern "C"
pe::plugin_pointer_type plugin_factory(
      const std::string& _plugin_name
    , const std::string&) {
    return pe::make(
                 _plugin_name
               , "irods_policy_access_time"
               , usage
               , access_time_policy);
} // plugin_factory
