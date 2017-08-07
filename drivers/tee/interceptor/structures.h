#ifndef STRUCTURES_H
#define STRUCTURES_H

// TODO: Change TEEC_Session for upgrade
//       optee_session might be the replacement

struct session {
	struct hlist_node hash_list;
	char 	     	 *abs_name;
	TEEC_Session 	 *sess;
	int               id;
	int          	  refcnt;
};

struct process {
	struct hlist_node   hash_list;
	int  			    procid;
	struct hlist_head   fd_list;
};

struct fd_struct {
	struct hlist_node   list; 
	int   				fd;
	struct session     *sess;
};
#endif /* STRUCTURES_H */
