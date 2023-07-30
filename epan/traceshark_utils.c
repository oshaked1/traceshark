#include "traceshark.h"

gpointer g_tree_get_preceding_node(GTree *tree, gconstpointer key)
{
    GTreeNode *res;

    // lower bound returns the first entry that has an equal or larger key,
    // and its previous entry will be the last one before our key.
    if ((res = g_tree_lower_bound(tree, key)) != NULL) {
        if ((res = g_tree_node_previous(res)) != NULL)
            return g_tree_node_value(res);
        
        // no previous entry
        return NULL;
    }

    // no lower bound, the last entry will be before our key
    if ((res = g_tree_node_last(tree)) != NULL)
        return g_tree_node_value(res);
    
    // no last entry, which means the tree is empty
    return NULL;
}

gpointer g_tree_get_following_node(GTree *tree, gconstpointer key)
{
    GTreeNode *res;

    // upper bound returns the first entry that has a larger key
    if ((res = g_tree_upper_bound(tree, key)) != NULL)
        return g_tree_node_value(res);
    
    // no upper bound
    return NULL;
}