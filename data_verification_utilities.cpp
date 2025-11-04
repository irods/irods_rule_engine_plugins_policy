#define  IRODS_QUERY_ENABLE_SERVER_SIDE_API
#include <irods/irods_query.hpp>
#include <irods/irods_resource_manager.hpp>
#include <irods/physPath.hpp>
#include <irods/irods_server_api_call.hpp>
#include <irods/apiNumber.h>
#include <irods/filesystem.hpp>
#include <irods/rsFileStat.hpp>

#include <boost/lexical_cast.hpp>
#include <fmt/format.h>

#include "data_verification_utilities.hpp"

extern irods::resource_manager resc_mgr;

namespace {

    auto throw_if_empty(
        const std::string& _variable,
        const std::string& _value)
    {
        if(_value.empty()) {
            THROW(SYS_INVALID_INPUT_PARAM,
                  fmt::format("{} is empty",
                  _variable));
        }
    } // throw_if_empty

    namespace verification_type {
        static const std::string catalog{"catalog"};
        static const std::string checksum{"checksum"};
        static const std::string filesystem{"filesystem"};
    };

    rodsLong_t get_file_size_from_filesystem(
        rsComm_t*          _comm,
        const std::string& _logical_path,
        const std::string& _resource_hierarchy,
        const std::string& _file_path )
    {
        fileStatInp_t stat_inp{};
        rstrcpy(stat_inp.objPath,  _logical_path.c_str(),  sizeof(stat_inp.objPath));
        rstrcpy(stat_inp.rescHier, _resource_hierarchy.c_str(), sizeof(stat_inp.rescHier));
        rstrcpy(stat_inp.fileName, _file_path.c_str(), sizeof(stat_inp.fileName));

        rodsStat_t *stat_out{};
        auto ret = irods::server_api_call(FILE_STAT_AN, _comm, &stat_inp, &stat_out);
        if(ret < 0) {
            free(stat_out);
            THROW(
                ret,
                fmt::format("rsFileStat of objPath [{}] rescHier [{}] fileName [{}] failed with [{}]"
                , stat_inp.objPath
                , stat_inp.rescHier
                , stat_inp.fileName
                , ret));
            return ret;
        }

        const auto size_in_vault = stat_out->st_size;
        free(stat_out);
        return size_in_vault;
    } // get_file_size_from_filesystem

    std::string get_leaf_resources_string(
        const std::string& _resource_name)
    {
        std::string leaf_id_str;

        // if the resource has no children then simply return
        irods::resource_ptr root_resc;
        irods::error err = resc_mgr.resolve(_resource_name, root_resc);
        if(!err.ok()) {
            THROW(err.code(), err.result());
        }

        try {
            std::vector<irods::resource_manager::leaf_bundle_t> leaf_bundles =
                resc_mgr.gather_leaf_bundles_for_resc(_resource_name);
            for(const auto & bundle : leaf_bundles) {
                for(const auto & leaf_id : bundle) {
                    leaf_id_str += fmt::format("'{}', ", leaf_id);
                } // for
            } // for
        }
        catch( const irods::exception & _e ) {
            throw;
        }

        // if there is no hierarchy
        if(leaf_id_str.empty()) {
            rodsLong_t resc_id;
            resc_mgr.hier_to_leaf_id(_resource_name, resc_id);
                    leaf_id_str += fmt::format("'{}'", resc_id);
        }

        return leaf_id_str;

    } // get_leaf_resources_string

    void capture_replica_attributes(
        rsComm_t*          _comm,
        const std::string& _logical_path,
        const std::string& _resource_name,
        std::string&       _file_path,
        std::string&       _data_size,
        std::string&       _data_hierarchy,
        std::string&       _data_checksum )
    {
        std::string coll_name, obj_name;

        irods::get_object_and_collection_from_path(
            _logical_path,
            coll_name,
            obj_name);

        const auto leaf_str  = get_leaf_resources_string(_resource_name);
        const auto query_str = fmt::format(
                               "SELECT DATA_PATH, DATA_RESC_HIER, DATA_SIZE, "
                               "DATA_CHECKSUM WHERE DATA_NAME = '{}' AND "
                               "COLL_NAME = '{}' AND DATA_RESC_ID IN ({})"
                               , obj_name
                               , coll_name
                               , leaf_str);
        irods::query<rsComm_t> qobj{_comm, query_str, 1};
        if(qobj.size() > 0) {
            const auto result = qobj.front();
            _file_path      = result[0];
            _data_hierarchy = result[1];
            _data_size      = result[2];
            _data_checksum  = result[3];

            return;
        }

        THROW(SYS_REPLICA_DOES_NOT_EXIST,
              fmt::format("replica for [{}] does not exist on resource [{}]"
              , _logical_path
              , _resource_name));

    } // capture_replica_attributes

} // namespace


namespace irods {

    void get_object_and_collection_from_path(
        const std::string& _logical_path,
        std::string&       _collection_name,
        std::string&       _object_name )
    {
        namespace bfs = boost::filesystem;

        try {
            bfs::path p(_logical_path);
            _collection_name = p.parent_path().string();
            _object_name     = p.filename().string();
        }
        catch(const bfs::filesystem_error& _e) {
            THROW(SYS_INVALID_FILE_PATH, _e.what());
        }
    } // get_object_and_collection_from_path

    std::string compute_checksum_for_resource(
        rsComm_t*          _comm,
        const std::string& _logical_path,
        const std::string& _resource_name )
    {
        // query if a checksum exists
        std::string coll_name, obj_name;
        get_object_and_collection_from_path(
            _logical_path,
            coll_name,
            obj_name);

        const auto query_str = fmt::format(
                               "SELECT DATA_CHECKSUM WHERE DATA_NAME = '{}'"
                               " AND COLL_NAME = '{}' AND RESC_NAME = '{}'"
                               , obj_name
                               , coll_name
                               , _resource_name);
        irods::query<rsComm_t> qobj(_comm, query_str, 1);
        if(qobj.size() > 0) {
            const auto& result = qobj.front();
            const auto& data_checksum = result[0];
            if(!data_checksum.empty()) {
                return data_checksum;
            }
        }

        // no checksum, compute one
        dataObjInp_t data_obj_inp{};
        irods::at_scope_exit clear_data_obj{
            [&data_obj_inp] { clearDataObjInp(&data_obj_inp); }};
        rstrcpy(data_obj_inp.objPath, _logical_path.c_str(), MAX_NAME_LEN);
        addKeyVal(&data_obj_inp.condInput, RESC_NAME_KW, _resource_name.c_str());

        char* checksum_pointer{};
        irods::at_scope_exit free_checksum_pointer{
            [&checksum_pointer] { free(checksum_pointer); }};
        const auto chksum_err = irods::server_api_call(DATA_OBJ_CHKSUM_AN, _comm, &data_obj_inp, &checksum_pointer);
        if(chksum_err < 0) {
            THROW(
                chksum_err,
                fmt::format(
                "checksum failed for [{}] on [{}]"
                , _logical_path
                , _resource_name));
        }

        std::string checksum{checksum_pointer};

        return checksum;

    } // compute_checksum_for_resource

    bool verify_replica_for_destination_resource(
        rsComm_t*          _comm,
        const std::string& _verification_type,
        const std::string& _logical_path,
        const std::string& _source_resource,
        const std::string& _destination_resource)
    {

        throw_if_empty("verification type",    _verification_type);
        throw_if_empty("logical path",         _logical_path);
        throw_if_empty("source resource",      _source_resource);
        throw_if_empty("desitnation resource", _destination_resource);

        std::string source_logical_path;
        std::string source_data_size;
        std::string source_data_hierarchy;
        std::string source_file_path;
        std::string source_data_checksum;

        capture_replica_attributes(
            _comm,
            _logical_path,
            _source_resource,
            source_file_path,
            source_data_size,
            source_data_hierarchy,
            source_data_checksum );

        std::string destination_logical_path;
        std::string destination_data_size;
        std::string destination_data_hierarchy;
        std::string destination_file_path;
        std::string destination_data_checksum;

        capture_replica_attributes(
            _comm,
            _logical_path,
            _destination_resource,
            destination_file_path,
            destination_data_size,
            destination_data_hierarchy,
            destination_data_checksum );

        if(_verification_type.size() == 0 ||
           verification_type::catalog == _verification_type) {

            // default verification type is 'catalog'
            if(source_data_size == destination_data_size) {
                return true;
            }
        }
        else if(verification_type::filesystem == _verification_type) {
            const auto fs_size = get_file_size_from_filesystem(
                                     _comm,
                                     _logical_path,
                                     destination_data_hierarchy,
                                     destination_file_path);

            const auto query_size = boost::lexical_cast<rodsLong_t>(source_data_size);

            return (fs_size == query_size);
        }
        else if(verification_type::checksum == _verification_type) {
            if(source_data_checksum.size() == 0) {
                source_data_checksum = compute_checksum_for_resource(
                                           _comm,
                                           _logical_path,
                                           _source_resource);
            }

            if(destination_data_checksum.size() == 0) {
                destination_data_checksum = compute_checksum_for_resource(
                                               _comm,
                                               _logical_path,
                                               _destination_resource);
            }

            return (source_data_checksum == destination_data_checksum);
        }
        else {
            THROW(
                SYS_INVALID_INPUT_PARAM,
                fmt::format("invalid verification type [()]",
                _verification_type));
        }

        return false;

    } // verify_replica_for_destination_resource

} // namespace irods


