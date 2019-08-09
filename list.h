/* SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: Marek Lindner <mareklindner@neomailbox.ch>
 */

#ifndef __AP51_FLASH_LIST_H__
#define __AP51_FLASH_LIST_H__

struct list {
	struct list *next;
	void *data;
};

#define slist_for_each(node, head) \
	for (node = (head); (node); node = node->next)

#define slist_for_each_safe(node, safe, head) \
	for (node = (head); \
	     (node) && (((safe) = node->next) || 1); \
	     node = safe)

static inline void list_prepend(struct list **list, struct list *list_item)
{
	if (!(*list)) {
		*list = list_item;
		return;
	}

	list_item->next = (*list)->next;
	(*list)->next = list_item;
}

#endif /* __AP51_FLASH_LIST_H__ */
