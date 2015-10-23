from optparse import make_option

from django.core.management.base import BaseCommand

from crits.core.mongo_tools import mongo_connector

import pprint

class Command(BaseCommand):
    """
    Gets a count of indicator types and object types in CRITs
    """

    help = "Gets a count of indicator types and object types in CRITs"

    option_list = BaseCommand.option_list + (
        make_option('--sort_count',
                    '-s',
                    dest='sort_count',
                    default=False,
                    action="store_true",
                    help='Sort by count instead of by the type\'s name.'
                    ),
        make_option('--agg_obj_by_collection',
                    '-a',
                    dest='agg_obj_by_collection',
                    default=False,
                    action="store_true",
                    help='For object types: Aggregate by collection instead of '
                         'combining all results.'
                    ),
    )

    all_object_collections = [
        "actors",
        "backdoors",
        "campaigns",
        "certificates",
        "domains",
        "email",
        "events",
        "exploits",
        "indicators",
        "ips",
        "pcaps",
        "raw_data",
        "sample",
        "screenshots",
        "targets",
        "yara_rules"
    ]

    def handle(self, *args, **kwargs):

        sort_count = kwargs.get('sort_count')
        agg_obj_by_collection = kwargs.get('agg_obj_by_collection')

        pp = pprint.PrettyPrinter(indent=4)

        self.aggregate_indicator_types(sort_count, pp)
        self.aggregate_object_types(sort_count, agg_obj_by_collection, pp)

    def aggregate_indicator_types(self, sort_count, pp):
        collection = "indicators"

        pipe = [ { "$group": {"_id":"$type" , "count":{"$sum": 1}}}, {"$sort": {"_id": 1}} ]

        if sort_count is True:
            pipe.append({"$sort": {"count": 1}})
        else:
            pipe.append({"$sort": {"_id": 1}})

        db = mongo_connector(collection)

        results = db.aggregate(pipeline=pipe)

        print "INDICATOR TYPES IN COLLECTION [%s]" % collection
        pp.pprint(results)
        print

    def aggregate_object_for_collection(self, collection, sort_count):
        pipe = [
            {"$unwind": "$objects"},
            {"$group" :
                {"_id":
                    {"obj_type":
                        {"$cond":
                            {"if":
                                {"$and":
                                    [{"$gt":["$objects.name", None] },
                                    {"$ne": ["$objects.type", "$objects.name"]}]
                                },
                                "then": {"$concat": [ "$objects.type", " - ", "$objects.name" ]},
                                "else": "$objects.type"
                            }
                        }
                    },
                    "count": {"$sum": 1}
                }
            }
        ]

        if sort_count is True:
            pipe.append({"$sort": {"count": 1}})
        else:
            pipe.append({"$sort": {"_id": 1}})

        db = mongo_connector(collection)

        results = db.aggregate(pipeline=pipe)

        return results

    def aggregate_object_types(self, sort_count, is_agg_per_collection, pp):

        results = {}

        for collection in self.all_object_collections:
            object_types = self.aggregate_object_for_collection(collection, sort_count)
            results[collection] = object_types

        if is_agg_per_collection:
            for collection in self.all_object_collections:
                print "OBJECT TYPES FOR COLLECTION: [%s]" % collection.upper()

                if len(results[collection]['result']) != 0:
                    pp.pprint(results[collection]['result'])
                else:
                    print "None found."

                print
        else:
            all_obj_types = {}

            for collection in self.all_object_collections:
                collection_results = results[collection]

                for collection_result in collection_results['result']:
                    obj_type = collection_result['_id']['obj_type']
                    all_obj_types[obj_type] =  collection_result['count'] + all_obj_types.get(obj_type, 0);

            print "OBJECT TYPES FOR ALL COLLECTIONS"

            if(sort_count):
                import operator
                sorted_x = sorted(all_obj_types.items(), key=operator.itemgetter(1))
                pp.pprint(sorted_x)
            else:
                pp.pprint(all_obj_types)

            print

        print
