#include "traceshark.h"

GTreeNode *g_tree_get_preceding_node(GTree *tree, gconstpointer key)
{
    GTreeNode *res;

    // lower bound returns the first entry that has an equal or larger key,
    // and its previous entry will be the last one before our key.
    if ((res = g_tree_lower_bound(tree, key)) != NULL)
        return g_tree_node_previous(res);

    // no lower bound, the last entry will be before our key
    return g_tree_node_last(tree);
}

gpointer g_tree_get_preceding_value(GTree *tree, gconstpointer key)
{
    GTreeNode *res = g_tree_get_preceding_node(tree, key);

    if (res != NULL)
        return g_tree_node_value(res);
    
    return NULL;
}

GTreeNode *g_tree_get_following_node(GTree *tree, gconstpointer key)
{
    // upper bound returns the first entry that has a larger key
    return g_tree_upper_bound(tree, key);
}

gpointer g_tree_get_following_value(GTree *tree, gconstpointer key)
{
    GTreeNode *res = g_tree_get_following_node(tree, key);

    if (res != NULL)
        return g_tree_node_value(res);
    
    return NULL;
}