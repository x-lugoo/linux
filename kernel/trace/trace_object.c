// SPDX-License-Identifier: GPL-2.0
/*
 * trace the kernel object in the kernel function parameter
 * Copyright (C) 2021 Jeff Xie <xiehuan09@gmail.com>
 */

#define pr_fmt(fmt) "trace_object: " fmt

#include "trace_output.h"

#define MAX_TRACED_OBJECT 5
#define OBJTRACE_CMD_LEN  16
#define OBJTRACE_CMD_ADD "add"
static LIST_HEAD(obj_data_head);
static const int max_args_num = 6;
static void exit_trace_object(struct trace_array *tr);
static int init_trace_object(struct trace_array *tr);

struct object_instance {
	void *obj;
	struct trace_array *tr;
};

/* objtrace private data */
struct objtrace_trigger_data {
	struct ftrace_event_field *field;
	char objtrace_cmd[OBJTRACE_CMD_LEN];
	struct trace_array *tr;
};

/* objtrace data with fops and objtrace_instances */
struct objtrace_data {
	struct list_head head;
	struct trace_array *tr;
	struct ftrace_ops fops;
	int num_traced_obj;
	struct object_instance traced_obj[MAX_TRACED_OBJECT];
	raw_spinlock_t obj_data_lock;
};

static struct objtrace_data *get_obj_data(struct trace_array *tr)
{
	struct objtrace_data *obj_data = NULL;

	list_for_each_entry(obj_data, &obj_data_head, head) {
		if (obj_data->tr == tr)
			break;
	}
	return obj_data;
}

static bool object_exist(void *obj, struct trace_array *tr)
{
	int i, max;
	struct objtrace_data *obj_data;

	obj_data = get_obj_data(tr);
	if (!obj_data)
		return false;

	max = READ_ONCE(obj_data->num_traced_obj);
	smp_rmb();
	for (i = 0; i < max; i++) {
		if (obj_data->traced_obj[i].obj == obj)
			return true;
	}
	return false;
}

static bool object_empty(struct trace_array *tr)
{
	struct objtrace_data *obj_data;

	obj_data = get_obj_data(tr);
	if (!obj_data)
		return false;

	return !READ_ONCE(obj_data->num_traced_obj);
}

static void set_trace_object(void *obj, struct trace_array *tr)
{
	unsigned long flags;
	struct object_instance *obj_ins;
	struct objtrace_data *obj_data;

	if (in_nmi())
		return;

	if (!obj && object_exist(obj, tr))
		return;

	obj_data = get_obj_data(tr);
	if (!obj_data)
		return;

	/* only this place has write operations */
	raw_spin_lock_irqsave(&obj_data->obj_data_lock, flags);
	if (READ_ONCE(obj_data->num_traced_obj) == MAX_TRACED_OBJECT) {
		trace_array_printk_buf(tr->array_buffer.buffer, _THIS_IP_,
				"object_pool is full, can't trace object:0x%px\n", obj);
		goto out;
	}
	obj_ins = &obj_data->traced_obj[READ_ONCE(obj_data->num_traced_obj)];
	obj_ins->obj = obj;
	obj_ins->tr = tr;
	/* make sure the num_traced_obj update always appears after traced_obj update */
	smp_wmb();
	obj_data->num_traced_obj++;
out:
	raw_spin_unlock_irqrestore(&obj_data->obj_data_lock, flags);
}

static void submit_trace_object(unsigned long ip, unsigned long parent_ip,
				 unsigned long object, struct trace_array *tr)
{

	struct trace_buffer *buffer = tr->array_buffer.buffer;
	struct ring_buffer_event *event;
	struct trace_object_entry *entry;
	unsigned int trace_ctx = 0;

	trace_ctx = tracing_gen_ctx();
	event = trace_buffer_lock_reserve(buffer, TRACE_OBJECT,
			sizeof(*entry), trace_ctx);
	if (!event)
		return;
	entry   = ring_buffer_event_data(event);
	entry->ip                       = ip;
	entry->parent_ip                = parent_ip;
	entry->object			= object;

	trace_buffer_unlock_commit(tr, buffer, event, trace_ctx);
}

static void
trace_object_events_call(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *op, struct ftrace_regs *fregs)
{
	struct pt_regs *pt_regs = ftrace_get_regs(fregs);
	struct trace_array *tr = op->private;
	struct trace_array_cpu *data;
	unsigned long obj;
	long disabled;
	int cpu, n;

	preempt_disable_notrace();

	cpu = raw_smp_processor_id();
	data = per_cpu_ptr(tr->array_buffer.data, cpu);
	disabled = atomic_inc_return(&data->disabled);
	if (likely(disabled == 1)) {
		if (object_empty(tr))
			goto out;
		for (n = 0; n < max_args_num; n++) {
			obj = regs_get_kernel_argument(pt_regs, n);
			if (object_exist((void *)obj, tr))
				submit_trace_object(ip, parent_ip, obj, tr);
		/* The parameters of a function may match multiple objects */
		}
	}
out:
	atomic_dec(&data->disabled);
	preempt_enable_notrace();
}

static void
trace_object_trigger(struct event_trigger_data *data,
		   struct trace_buffer *buffer,  void *rec,
		   struct ring_buffer_event *event)
{
	struct objtrace_trigger_data *obj_data = data->private_data;
	struct trace_array *tr = obj_data->tr;
	struct ftrace_event_field *field;
	void *obj = NULL;

	field = obj_data->field;
	memcpy(&obj, rec + field->offset, sizeof(obj));
	set_trace_object(obj, tr);
}

static void
trace_object_trigger_free(struct event_trigger_data *data)
{
	struct objtrace_trigger_data *obj_data = data->private_data;

	if (WARN_ON_ONCE(data->ref <= 0))
		return;

	data->ref--;
	if (!data->ref) {
		exit_trace_object(obj_data->tr);
		kfree(data->private_data);
		trigger_data_free(data);
	}
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

static int
event_trigger_print(const char *name, struct seq_file *m,
		void *data, char *filter_str, void *objtrace_data)
{
	long count = (long)data;
	struct objtrace_trigger_data *obj_data = objtrace_data;

	seq_puts(m, name);

	seq_printf(m, ":%s", obj_data->objtrace_cmd);
	seq_printf(m, ":%s", obj_data->field->name);

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

static int event_object_trigger_init(struct event_trigger_data *data)
{
	struct objtrace_trigger_data *obj_data = data->private_data;
	int ret;

	if (!data->ref) {
		ret = init_trace_object(obj_data->tr);
		if (ret)
			return ret;
	}
	data->ref++;
	return 0;
}

static int
trace_object_trigger_print(struct seq_file *m, struct event_trigger_data *data)
{
	return event_trigger_print("objtrace", m, (void *)data->count,
				   data->filter_str, data->private_data);
}

static struct event_trigger_ops objecttrace_trigger_ops = {
	.trigger		= trace_object_trigger,
	.print			= trace_object_trigger_print,
	.init			= event_object_trigger_init,
	.free			= trace_object_trigger_free,
};

static struct event_trigger_ops objecttrace_count_trigger_ops = {
	.trigger		= trace_object_count_trigger,
	.print			= trace_object_trigger_print,
	.init			= event_object_trigger_init,
	.free			= trace_object_trigger_free,
};

static struct event_trigger_ops *
objecttrace_get_trigger_ops(char *cmd, char *param)
{
	return param ? &objecttrace_count_trigger_ops : &objecttrace_trigger_ops;
}

static bool field_exist(struct trace_event_file *file,
			struct event_command *cmd_ops,
			const char *field_name)
{
	struct event_trigger_data *data;
	struct objtrace_trigger_data *obj_data;

	lockdep_assert_held(&event_mutex);

	list_for_each_entry(data, &file->triggers, list) {
		if (data->cmd_ops->trigger_type == cmd_ops->trigger_type) {
			obj_data = data->private_data;
			if (!strcmp(obj_data->field->name, field_name))
				return true;
		}
	}

	return false;
}

static int
event_object_trigger_parse(struct event_command *cmd_ops,
		       struct trace_event_file *file,
		       char *glob, char *cmd, char *param_and_filter)
{
	struct event_trigger_data *trigger_data;
	struct objtrace_trigger_data *obj_data;
	struct ftrace_event_field *field;
	char *objtrace_cmd, *arg;
	char *param, *filter;
	int ret;
	bool remove;

	remove = event_trigger_check_remove(glob);

	/*
	 * separate the param and the filter:
	 * objtrace:add:OBJ[:COUNT] [if filter]
	 */
	ret = event_trigger_separate_filter(param_and_filter, &param, &filter, true);
	if (ret)
		return ret;

	objtrace_cmd = strsep(&param, ":");
	if (!objtrace_cmd || strcmp(objtrace_cmd, OBJTRACE_CMD_ADD)) {
		pr_err("error objtrace command\n");
		return -EINVAL;
	}

	arg = strsep(&param, ":");
	if (!arg)
		return -EINVAL;

	field = trace_find_event_field(file->event_call, arg);
	if (!field)
		return -EINVAL;

	if (field->size != sizeof(void *)) {
		pr_err("the size of the %s should be:%zu\n", field->name, sizeof(void *));
		return -EINVAL;
	}

	if (remove && !field_exist(file, cmd_ops, field->name))
		return -ENOENT;

	obj_data = kzalloc(sizeof(*obj_data), GFP_KERNEL);
	if (!obj_data)
		return -ENOMEM;

	obj_data->field = field;
	obj_data->tr = file->tr;
	snprintf(obj_data->objtrace_cmd, OBJTRACE_CMD_LEN, objtrace_cmd);

	trigger_data = event_trigger_alloc(cmd_ops, cmd, param, obj_data);
	if (!trigger_data) {
		kfree(obj_data);
		return -ENOMEM;
	}
	if (remove) {
		event_trigger_unregister(cmd_ops, file, glob+1, trigger_data);
		kfree(obj_data);
		kfree(trigger_data);
		return 0;
	}

	ret = event_trigger_parse_num(param, trigger_data);
	if (ret)
		goto out_free;

	ret = event_trigger_set_filter(cmd_ops, file, filter, trigger_data);
	if (ret < 0)
		goto out_free;

	ret = event_trigger_register(cmd_ops, file, glob, trigger_data);
	if (ret)
		goto out_free;

	return ret;

 out_free:
	event_trigger_reset_filter(cmd_ops, trigger_data);
	kfree(obj_data);
	kfree(trigger_data);
	return ret;
}

static struct event_command trigger_object_cmd = {
	.name			= "objtrace",
	.trigger_type		= ETT_TRACE_OBJECT,
	.flags			= EVENT_CMD_FL_NEEDS_REC,
	.parse			= event_object_trigger_parse,
	.reg			= register_trigger,
	.unreg			= unregister_trigger,
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

int allocate_objtrace_data(struct trace_array *tr)
{
	struct objtrace_data *obj_data;
	struct ftrace_ops *fops;

	obj_data = kzalloc(sizeof(*obj_data), GFP_KERNEL);
	if (!obj_data)
		return -ENOMEM;

	raw_spin_lock_init(&obj_data->obj_data_lock);
	obj_data->tr = tr;
	fops = &obj_data->fops;
	fops->func = trace_object_events_call;
	fops->flags = FTRACE_OPS_FL_SAVE_REGS;
	fops->private = tr;
	list_add(&obj_data->head, &obj_data_head);

	tr->obj_data = obj_data;

	return 0;
}

static int init_trace_object(struct trace_array *tr)
{
	int ret;

	ret = register_ftrace_function(&tr->obj_data->fops);
	WARN_ON(ret < 0);

	return ret;
}

void free_objtrace_data(struct trace_array *tr)
{
	kfree(tr->obj_data);
	tr->obj_data = NULL;
}

static void exit_trace_object(struct trace_array *tr)
{
	struct objtrace_data *obj_data = tr->obj_data;

	obj_data->num_traced_obj = 0;
	WARN_ONCE(unregister_ftrace_function(&obj_data->fops),
			"can't unregister ftrace for trace object\n");
}
