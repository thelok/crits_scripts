# crits_scripts

## get_indicator_types.py

Copy crits/core/managament/commands/get_indicator_types.py into your crits/core/managament/commands/ directory.

```
# Usage: python manage.py get_indicator_types [options]

Gets a count of indicator types and object types in CRITs

Options:
  -s, --sort_count      Sort by count instead of by the type's name.
  -a, --agg_obj_by_collection
                        Perform lookups for all entries.  Default: Only
                        perform lookups on entries with blank Firstname
  -h, --help            show this help message and exit

```
