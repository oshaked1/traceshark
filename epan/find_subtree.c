/**
 * Code taken from packet-f5ethtrailer.c
*/
#include <wireshark.h>

#include "traceshark.h"

/** Structure used as the anonymous data in the proto_tree_children_foreach() function */
struct subtree_search {
    proto_tree *tree; /**< The matching tree that we found */
    gint hf;          /**< The type of tree that we are looking for. */
};

/*-----------------------------------------------------------------------------------------------*/
/**
 * @brief Function to see if a node is of a particular type and return it if it is a tree.
 *
 * @param pn   A pointer to the proto_node being looked at.
 * @param data A pointer to the subtree_search structure with search criteria and results.
 */
static void
compare_subtree(proto_node *pn, gpointer data)
{
    struct subtree_search *search_struct;
    search_struct = (struct subtree_search *)data;

    if (pn && pn->finfo && pn->finfo->hfinfo && pn->finfo->hfinfo->id == search_struct->hf) {
        search_struct->tree = proto_item_get_subtree(pn);
    }
} /* compare_subtree() */

/*-----------------------------------------------------------------------------------------------*/
/**
 * @brief Function to search child trees (one level) for a tree of a specific type.
 *
 * @param tree A pointer to the proto_tree being looked at.
 * @param hf   The register hfinfo id that we are looking for.
 * @return     The tree that was found or NULL if it was not found.
 */
proto_tree *
find_subtree(proto_tree *tree, gint hf)
{
    struct subtree_search search_struct;

    if (tree == NULL || hf == -1)
        return NULL;
    search_struct.tree = NULL;
    search_struct.hf   = hf;
    proto_tree_children_foreach(tree, compare_subtree, &search_struct);
    return search_struct.tree;
} /* find_subtree() */