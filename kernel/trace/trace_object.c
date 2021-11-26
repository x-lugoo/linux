// SPDX-License-Identifier: GPL-2.0
/*
 * trace any object
 * Copyright (C) 2021 Jeff Xie <xiehuan09@gmail.com>
 */

#define pr_fmt(fmt) "trace_object: " fmt

#include "trace_output.h"
#include <linux/freelist.h>

static DEFINE_PER_CPU(atomic_t, trace_object_event_disable);
static struct trace_event_file event_trace_file;
static const int max_obj_pool = 10;
static atomic_t trace_object_ref;
static int exit_trace_object(void);
static int init_trace_object(void);

struct objtrace_trigger_data {
	struct ftrace_event_field *field;
	long offset;
	int type_size;
};

struct objtrace_fetch_type {
	char *name;
	int type_size;
};

struct object_instance {
	void *object;
	int obj_type_size;
	struct freelist_node freelist;
};

struct obj_pool {
	int maxactive;
	atomic_t nobject;
	struct freelist_head product_freelist;
	struct freelist_head customer_freelist;
};
static struct obj_pool *obj_pool;

static bool object_exist(void *obj)
{
	struct freelist_node *node;
	struct object_instance *inst;
	bool ret = false;

	node = obj_pool->customer_freelist.head;

	while (node) {
		inst = container_of(node, struct object_instance, freelist);
		if (inst->object == obj) {
			ret = true;
			goto out;
		}
		node = node->next;
	}
out:
	return ret;
}

static bool object_empty(void)
{
	bool ret;

	ret = atomic_read(&obj_pool->nobject) == 0;

	return ret;
}

static void set_trace_object(void *obj, int type_size)
{
	struct freelist_node *fn;
	struct object_instance *ins;

	if (!obj)
		return;

	if (object_exist(obj))
		goto out;

	fn = freelist_try_get(&obj_pool->product_freelist);
	if (!fn) {
		trace_printk("object_pool is full, can't trace object:0x%px\n", obj);
		return;
	}

	ins = container_of(fn, struct object_instance, freelist);
	ins->object = obj;
	ins->obj_type_size = type_size;

	freelist_add(&ins->freelist, &obj_pool->customer_freelist);
	atomic_inc(&obj_pool->nobject);

out:
	return;
}

static inline void free_objects(struct freelist_node *node)
{

	struct object_instance *inst;

	while (node) {
		inst = container_of(node, struct object_instance, freelist);
		node = node->next;
		kfree(inst);
	}
}

static inline void free_object_pool(void)
{
	free_objects(obj_pool->product_freelist.head);
	free_objects(obj_pool->customer_freelist.head);
	kfree(obj_pool);
}


static int init_object_pool(void)
{
	struct object_instance *inst;
	int i, ret = 0;

	obj_pool = kzalloc(sizeof(*obj_pool), GFP_KERNEL);
	if (!obj_pool) {
		ret = -ENOMEM;
		goto out;
	}
	obj_pool->maxactive = max_obj_pool;
	obj_pool->product_freelist.head = NULL;
	obj_pool->customer_freelist.head = NULL;

	for (i = 0; i < obj_pool->maxactive; i++) {
		inst = kzalloc(sizeof(*inst), GFP_KERNEL);
		if (!inst) {
			free_object_pool();
			ret = -ENOMEM;
			goto out;
		}
		freelist_add(&inst->freelist, &obj_pool->product_freelist);
	}
out:
	return ret;
}

static void submit_trace_object(unsigned long ip, unsigned long parent_ip,
				 unsigned long object, unsigned long value)
{

	struct trace_buffer *buffer;
	struct ring_buffer_event *event;
	struct trace_object_entry *entry;
	int pc;

	pc = preempt_count();
	event = trace_event_buffer_lock_reserve(&buffer, &event_trace_file,
			TRACE_OBJECT, sizeof(*entry), pc);
	if (!event)
		return;
	entry   = ring_buffer_event_data(event);
	entry->ip                       = ip;
	entry->parent_ip                = parent_ip;
	entry->object			= object;
	entry->value			= value;

	event_trigger_unlock_commit(&event_trace_file, buffer, event,
		entry, pc);
}

static void
trace_object_events_call(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *op, struct ftrace_regs *fregs)
{
	struct freelist_node *node;
	struct object_instance *inst;
	unsigned long val = 0;
	long disabled;
	int cpu;

	preempt_disable_notrace();

	cpu = raw_smp_processor_id();
	disabled = atomic_inc_return(&per_cpu(trace_object_event_disable, cpu));

	if (disabled != 1)
		goto out;

	if (object_empty())
		goto out;

	node = obj_pool->customer_freelist.head;

	while (node) {
		inst = container_of(node, struct object_instance, freelist);
		if (copy_from_kernel_nofault(&val, inst->object, inst->obj_type_size))
			goto out;
		submit_trace_object(ip, parent_ip, (unsigned long)inst->object, val);
		node = node->next;
	}

out:
	atomic_dec(&per_cpu(trace_object_event_disable, cpu));
	preempt_enable_notrace();
}

static struct ftrace_ops trace_ops = {
	.func  = trace_object_events_call,
	.flags = FTRACE_OPS_FL_SAVE_REGS,
};

static void
trace_object_trigger(struct event_trigger_data *data,
		   struct trace_buffer *buffer,  void *rec,
		   struct ring_buffer_event *event)
{
	struct objtrace_trigger_data *obj_data = data->private_data;
	struct ftrace_event_field *field;
	void *obj, *val = NULL;

	field = obj_data->field;
	memcpy(&val, rec + field->offset, sizeof(val));
	obj = val + obj_data->offset;
	set_trace_object(obj, obj_data->type_size);
}

static void
trace_object_trigger_free(struct event_trigger_ops *ops,
		   struct event_trigger_data *data)
{
	if (WARN_ON_ONCE(data->ref <= 0))
		return;

	data->ref--;
	if (!data->ref)
		trigger_data_free(data);
}

static void
trace_object_count_trigger(struct event_trigger_data *data,
			 struct trace_buffer *buffer, void *rec,
			 struct ring_buffer_event *event)
{
	if (!data->count)
		return;

	if (data->count != -1)
		(data->count)--;

	trace_object_trigger(data, buffer, rec, event);
}

static int event_object_trigger_init(struct event_trigger_ops *ops,
		       struct event_trigger_data *data)
{
	data->ref++;
	return 0;
}

static int
event_trigger_print(const char *name, struct seq_file *m,
		    void *data, char *filter_str)
{
	long count = (long)data;

	seq_puts(m, name);

	if (count == -1)
		seq_puts(m, ":unlimited");
	else
		seq_printf(m, ":count=%ld", count);

	if (filter_str)
		seq_printf(m, " if %s\n", filter_str);
	else
		seq_putc(m, '\n');

	return 0;
}

static int
trace_object_trigger_print(struct seq_file *m, struct event_trigger_ops *ops,
			 struct event_trigger_data *data)
{
	return event_trigger_print("objtrace", m, (void *)data->count,
				   data->filter_str);
}


static struct event_trigger_ops objecttrace_trigger_ops = {
	.func			= trace_object_trigger,
	.print			= trace_object_trigger_print,
	.init			= event_object_trigger_init,
	.free			= trace_object_trigger_free,
};

static struct event_trigger_ops objecttrace_count_trigger_ops = {
	.func			= trace_object_count_trigger,
	.print			= trace_object_trigger_print,
	.init			= event_object_trigger_init,
	.free			= trace_object_trigger_free,
};

static struct event_trigger_ops *
objecttrace_get_trigger_ops(char *cmd, char *param)
{
	return param ? &objecttrace_count_trigger_ops : &objecttrace_trigger_ops;
}

static int register_object_trigger(char *glob, struct event_trigger_ops *ops,
			    struct event_trigger_data *data,
			    struct trace_event_file *file)
{
	struct event_trigger_data *test;
	int ret = 0;

	lockdep_assert_held(&event_mutex);

	list_for_each_entry(test, &file->triggers, list) {
		if (test->cmd_ops->trigger_type == data->cmd_ops->trigger_type) {
			ret = -EEXIST;
			goto out;
		}
	}

	if (data->ops->init) {
		ret = data->ops->init(data->ops, data);
		if (ret < 0)
			goto out;
	}

	list_add_rcu(&data->list, &file->triggers);
	ret++;

	update_cond_flag(file);
	if (trace_event_trigger_enable_disable(file, 1) < 0) {
		list_del_rcu(&data->list);
		update_cond_flag(file);
		ret--;
	}
	init_trace_object();
out:
	return ret;
}

static void unregister_object_trigger(char *glob, struct event_trigger_ops *ops,
			       struct event_trigger_data *test,
			       struct trace_event_file *file)
{
	struct event_trigger_data *data;
	bool unregistered = false;

	lockdep_assert_held(&event_mutex);

	list_for_each_entry(data, &file->triggers, list) {
		if (data->cmd_ops->trigger_type == test->cmd_ops->trigger_type) {
			unregistered = true;
			list_del_rcu(&data->list);
			trace_event_trigger_enable_disable(file, 0);
			update_cond_flag(file);
			break;
		}
	}

	if (unregistered && data->ops->free) {
		data->ops->free(data->ops, data);
		exit_trace_object();
	}
}

static const struct objtrace_fetch_type objtrace_fetch_types[] = {
	{"u8", 1},
	{"s8", 1},
	{"x8", 1},
	{"u16", 2},
	{"s16", 2},
	{"x16", 2},
	{"u32", 4},
	{"s32", 4},
	{"x32", 4},
	{"u64", 8},
	{"s64", 8},
	{"x64", 8},
	{}
};

static int
event_object_trigger_callback(struct event_command *cmd_ops,
		       struct trace_event_file *file,
		       char *glob, char *cmd, char *param)
{
	struct event_trigger_data *trigger_data;
	struct event_trigger_ops *trigger_ops;
	struct objtrace_trigger_data *obj_data;
	struct trace_event_call *call;
	struct ftrace_event_field *field;
	char *objtrace_cmd;
	long offset = 0;
	char *trigger = NULL;
	char *arg, *type, *tr, *tr_end;
	char *number;
	int ret, i, type_size = 0;

	ret = -EINVAL;
	if (!param)
		goto out;

	/* separate the trigger from the filter (c:a:n [if filter]) */
	trigger = strsep(&param, " \t");
	if (!trigger)
		goto out;
	if (param) {
		param = skip_spaces(param);
		if (!*param)
			param = NULL;
	}

	objtrace_cmd = strsep(&trigger, ":");
	if (!objtrace_cmd || strcmp(objtrace_cmd, "add"))
		goto out;

	arg = strsep(&trigger, ":");
	if (!arg)
		goto out;

	tr = strchr(arg, '(');
	/* now force to get the value of the val. */
	if (!tr)
		goto out;
	tr_end = strchr(tr, ')');
	if (!tr_end)
		goto out;
	*tr++ = '\0';
	*tr_end = '\0';
	ret = kstrtol(arg, 0, &offset);
	if (ret)
		goto out;
	arg = tr;
	ret = -EINVAL;
	if (!trigger)
		goto out;

	type = strsep(&trigger, ":");
	if (!type)
		goto out;
	for (i = 0; objtrace_fetch_types[i].name; i++) {
		if (strcmp(objtrace_fetch_types[i].name, type) == 0) {
			type_size = objtrace_fetch_types[i].type_size;
			break;
		}
	}

	if (type_size == 0)
		goto out;


	call = file->event_call;
	field = trace_find_event_field(call, arg);
	if (!field)
		goto out;

	trigger_ops = cmd_ops->get_trigger_ops(cmd, trigger);

	ret = -ENOMEM;
	obj_data = kzalloc(sizeof(*obj_data), GFP_KERNEL);
	if (!obj_data)
		goto out;

	obj_data->field = field;
	obj_data->offset = offset;
	obj_data->type_size = type_size;

	trigger_data = kzalloc(sizeof(*trigger_data), GFP_KERNEL);
	if (!trigger_data) {
		kfree(obj_data);
		goto out;
	}

	trigger_data->count = -1;
	trigger_data->ops = trigger_ops;
	trigger_data->cmd_ops = cmd_ops;
	trigger_data->private_data = obj_data;
	INIT_LIST_HEAD(&trigger_data->list);
	INIT_LIST_HEAD(&trigger_data->named_list);

	if (glob[0] == '!') {
		cmd_ops->unreg(glob+1, trigger_ops, trigger_data, file);
		kfree(obj_data);
		kfree(trigger_data);
		ret = 0;
		goto out;
	}

	if (trigger) {
		number = strsep(&trigger, ":");

		ret = -EINVAL;
		if (!strlen(number))
			goto out_free;

		/*
		 * We use the callback data field (which is a pointer)
		 * as our counter.
		 */
		ret = kstrtoul(number, 0, &trigger_data->count);
		if (ret)
			goto out_free;
	}

	if (!param) /* if param is non-empty, it's supposed to be a filter */
		goto out_reg;

	if (!cmd_ops->set_filter)
		goto out_reg;

	ret = cmd_ops->set_filter(param, trigger_data, file);
	if (ret < 0)
		goto out_free;

 out_reg:
	/* Up the trigger_data count to make sure reg doesn't free it on failure */
	event_object_trigger_init(trigger_ops, trigger_data);
	ret = cmd_ops->reg(glob, trigger_ops, trigger_data, file);
	/*
	 * The above returns on success the # of functions enabled,
	 * but if it didn't find any functions it returns zero.
	 * Consider no functions a failure too.
	 */
	if (!ret) {
		cmd_ops->unreg(glob, trigger_ops, trigger_data, file);
		ret = -ENOENT;
	} else if (ret > 0)
		ret = 0;

	/* Down the counter of trigger_data or free it if not used anymore */
	trace_object_trigger_free(trigger_ops, trigger_data);
 out:
	return ret;

 out_free:
	if (cmd_ops->set_filter)
		cmd_ops->set_filter(NULL, trigger_data, NULL);
	kfree(obj_data);
	kfree(trigger_data);
	goto out;
}

static struct event_command trigger_object_cmd = {
	.name			= "objtrace",
	.trigger_type		= ETT_TRACE_OBJECT,
	.flags			= EVENT_CMD_FL_NEEDS_REC,
	.func			= event_object_trigger_callback,
	.reg			= register_object_trigger,
	.unreg			= unregister_object_trigger,
	.get_trigger_ops	= objecttrace_get_trigger_ops,
	.set_filter		= set_trigger_filter,
};

__init int register_trigger_object_cmd(void)
{
	int ret;

	ret = register_event_command(&trigger_object_cmd);
	WARN_ON(ret < 0);

	return ret;
}

static int init_trace_object(void)
{
	int ret;

	if (atomic_inc_return(&trace_object_ref) != 1) {
		ret = 0;
		goto out;
	}

	ret = init_object_pool();
	if (ret)
		goto out;

	event_trace_file.tr = top_trace_array();
	if (WARN_ON(!event_trace_file.tr)) {
		ret = -1;
		goto out;
	}
	ret = register_ftrace_function(&trace_ops);
out:
	return ret;
}

static int exit_trace_object(void)
{
	int ret;

	if (WARN_ON_ONCE(atomic_read(&trace_object_ref) <= 0))
		goto out;

	if (atomic_dec_return(&trace_object_ref) != 0) {
		ret = 0;
		goto out;
	}

	ret = unregister_ftrace_function(&trace_ops);
	if (ret) {
		pr_err("can't unregister ftrace for trace object\n");
		goto out;
	}
	free_object_pool();
out:
	return ret;
}
