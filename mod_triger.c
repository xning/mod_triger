/* 
 * mod_triger.c: Add our scripts codes in the beginning or end of response
 * in the fly, that these scripts codes make custom-made responses for us.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "apr_general.h"
#include "apr_strings.h"
#include "apr_strmatch.h"
#include "apr_lib.h"
#include "util_filter.h"
#include "apr_buckets.h"
#include "http_request.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include <string.h>

#define DEFAULT_ENABLED 0
#define DEFAULT_INHERIT 1
#define DEFAULT_JS "<script>alert('Hello from mod_triger')</script>"
#define HTML_CTYPE "text/html"
#define XHTML_CTYPE "application/xhtml+xml"
#define DEFAULT_CHK_LEN 256
#define DEFAULT_FULL_CHK 0
#define VERSION 0.81
#define AUTHOR "xning@redhat.com"

module AP_MODULE_DECLARE_DATA triger_module;
static const char triger_filter_name[] = "TRIGER";

typedef struct triger_ctype {
    struct triger_ctype *prev;
    struct triger_ctype *next;
    char *data;
} triger_ctype_t;

typedef struct {
    int enabled;
    int inherit;
    char *js;
    triger_ctype_t *ctypes;
    apr_size_t chk_len;
    int full_chk;
    int default_enabled;
    int default_inherit;
    char *default_js;
    triger_ctype_t *default_ctypes;
    apr_size_t default_chk_len;
    int default_full_chk;
} triger_conf_t;

typedef struct triger_bucket {
    apr_size_t len;
    apr_size_t limit;
    const char *data;
    apr_bucket *b;
    apr_size_t body_end_tag_pos;
    apr_size_t html_end_tag_pos;
    apr_size_t html_start_tag_pos;
    apr_size_t head_start_tag_pos;
    apr_size_t body_start_tag_pos;
} triger_bucket_t;

typedef struct {
    int find;
    unsigned int times;
    int unknown_start_tag_find;
    int unknown_end_tag_find;
    int no_tag_find;
    int doctype_tag_find;
    int html_start_tag_find;
    int head_start_tag_find;
    int body_start_tag_find;
    int body_end_tag_find;
    int html_end_tag_find;
    triger_bucket_t *triger_bucket;
    int head_check;
} triger_module_ctx_t;

enum http_comments_type {
    html_comment,		/* <!-- --> */
    xml_comment,		/* <![CDATA[ ]]> */
    microsoft_comment		/* <comment> </comment> */
};

static void *create_triger_dir_config(apr_pool_t * pool, char *dumm)
{
    triger_ctype_t *m, *n;
    triger_conf_t *rv = apr_pcalloc(pool, sizeof(*rv));
    if (!rv)
	goto last;

    rv->enabled = -1;
    rv->inherit = -1;
    rv->js = NULL;
    rv->ctypes = NULL;
    rv->chk_len = 0;
    rv->full_chk = -1;

    rv->default_enabled = DEFAULT_ENABLED;
    rv->default_inherit = DEFAULT_INHERIT;
    rv->default_js = apr_pstrdup(pool, DEFAULT_JS);
    if (!rv->default_js)
	return NULL;

    m = apr_pcalloc(pool, sizeof(triger_ctype_t));
    if (!m)
	return NULL;
    m->prev = m->next = NULL;
    m->data = apr_pstrdup(pool, HTML_CTYPE);
    if (!m->data)
	return NULL;

    n = apr_pcalloc(pool, sizeof(triger_ctype_t));
    if (!n)
	return NULL;
    n->prev = n->next = NULL;
    n->data = apr_pstrdup(pool, XHTML_CTYPE);
    if (!n->data)
	return NULL;

    m->prev = m->next = n;
    n->prev = m;
    rv->default_ctypes = m;

    rv->default_chk_len = DEFAULT_CHK_LEN;
    rv->default_full_chk = DEFAULT_FULL_CHK;
  last:
    return (void *) rv;
}

static void *merge_triger_dir_config(apr_pool_t * pool, void *BASE,
				     void *ADD)
{
    triger_ctype_t *m, *n;
    triger_conf_t *base = (triger_conf_t *) BASE;
    triger_conf_t *add = (triger_conf_t *) ADD;

    if (!base)
	return add;

    triger_conf_t *conf =
	(triger_conf_t *) apr_palloc(pool, sizeof(triger_conf_t));
    if (!conf)
	goto last;

    conf->inherit = add->inherit;

    if (conf->inherit) {
	if (add->enabled == -1 && base->enabled != -1)
	    conf->enabled = base->enabled;
	else if (add->enabled != -1)
	    conf->enabled = add->enabled;
	else
	    conf->enabled = add->default_enabled;

	if (add->js && base->js) {
	    conf->js = apr_pstrcat(pool, add->js, base->js, NULL);
	    if (!conf->js)
		goto last;
	} else if (add->js)
	    conf->js = add->js;
	else if (base->js)
	    conf->js = base->js;
	else
	    conf->js = add->default_js;

	if (add->ctypes && base->ctypes) {
	    m = add->ctypes->prev;
	    n = base->ctypes->prev;
	    m->next = base->ctypes;
	    base->ctypes->prev = m;

	    add->ctypes->prev = n;
	    conf->ctypes = add->ctypes;
	} else if (add->ctypes)
	    conf->ctypes = add->ctypes;
	else if (base->ctypes)
	    conf->ctypes = base->ctypes;
	else
	    conf->ctypes = add->default_ctypes;

	if (add->chk_len == 0 && base->chk_len != 0)
	    conf->chk_len = base->chk_len;
	else if (add->chk_len != 0 && base->chk_len == 0)
	    conf->chk_len = add->chk_len;
	else if (add->chk_len != 0 && base->chk_len != 0)
	    conf->chk_len =
		add->chk_len >
		base->chk_len ? add->chk_len : base->chk_len;
	else
	    conf->chk_len = add->default_chk_len;

	if (add->full_chk == -1 && base->full_chk != -1)
	    conf->full_chk = base->full_chk;
	else if (add->full_chk != -1)
	    conf->full_chk = add->full_chk;
	else
	    conf->full_chk = add->default_full_chk;

    } else {
	conf->enabled =
	    add->enabled != -1 ? add->enabled : add->default_enabled;
	conf->js = add->js ? add->js : add->default_js;
	conf->ctypes = add->ctypes ? add->ctypes : add->default_ctypes;
	conf->chk_len =
	    add->chk_len != 0 ? add->chk_len : add->default_chk_len;
	conf->full_chk =
	    add->full_chk != -1 ? add->full_chk : add->default_full_chk;
    }

  last:
    return (void *) conf;
}

static int is_this_html(request_rec * r)
{

    triger_ctype_t *t;
    const char *ctype_line_val =
	apr_table_get(r->headers_out, "Content-Type");

    if (!ctype_line_val) {
	if (r->content_type)
	    ctype_line_val = apr_pstrdup(r->pool, r->content_type);
	else
	    return 0;
    }

    const char *ctype = ap_getword(r->pool, &ctype_line_val, ';');
    if (!ctype)
	return 0;

    triger_conf_t *cfg =
	ap_get_module_config(r->per_dir_config, &triger_module);

    if (!cfg)
	return 0;

    for (t = cfg->ctypes; t; t = t->next)
	if (t->data)
	    if (apr_strnatcasecmp(t->data, ctype) == 0)
		return 1;
    return 0;
}

static triger_bucket_t *get_triger_bucket(ap_filter_t * f, apr_bucket * b)
{
    const char *data;
    apr_size_t len = 0;
    triger_module_ctx_t *ctx = f->ctx;
    triger_bucket_t *rv = ctx->triger_bucket;

    rv->len = 0;
    rv->data = NULL;
    rv->b = NULL;
    rv->body_end_tag_pos = rv->body_start_tag_pos =
	rv->html_start_tag_pos = rv->head_start_tag_pos =
	rv->body_start_tag_pos = -1;
    apr_bucket_read(b, &data, &len, APR_BLOCK_READ);

    rv->len = len;
    rv->data = data;
    rv->b = b;
    return rv;
}

static triger_bucket_t *get_data_at_head(ap_filter_t * f,
					 apr_bucket_brigade * bb)
{
    const char *data;
    apr_bucket *b = APR_BRIGADE_FIRST(bb);
    apr_size_t len = 0;
    triger_module_ctx_t *ctx = f->ctx;
    triger_bucket_t *rv = ctx->triger_bucket;

    rv->len = 0;
    rv->data = NULL;
    rv->b = NULL;
    rv->body_end_tag_pos = rv->body_start_tag_pos =
	rv->html_start_tag_pos = rv->head_start_tag_pos =
	rv->body_start_tag_pos = -1;

    while (APR_BUCKET_IS_METADATA(b) && b != APR_BRIGADE_SENTINEL(bb))
	b = APR_BUCKET_NEXT(b);

    if (APR_BUCKET_IS_METADATA(b) || b == APR_BRIGADE_SENTINEL(bb))
	return rv;

    apr_bucket_read(b, &data, &len, APR_BLOCK_READ);

    rv->len = len;
    rv->data = data;
    rv->b = b;
    return rv;
}

static triger_bucket_t *get_data_at_tail(ap_filter_t * f,
					 apr_bucket_brigade * bb)
{
    const char *data;
    apr_bucket *b = APR_BRIGADE_LAST(bb);
    apr_size_t len = 0;
    triger_module_ctx_t *ctx = f->ctx;
    triger_bucket_t *rv = ctx->triger_bucket;

    rv->len = 0;
    rv->data = NULL;
    rv->b = NULL;
    rv->body_end_tag_pos = rv->body_start_tag_pos =
	rv->html_start_tag_pos = rv->head_start_tag_pos =
	rv->body_start_tag_pos = -1;


    while (APR_BUCKET_IS_METADATA(b) && b != APR_BRIGADE_SENTINEL(bb))
	b = APR_BUCKET_PREV(b);

    if (APR_BUCKET_IS_METADATA(b) || b == APR_BRIGADE_SENTINEL(bb))
	return rv;

    apr_bucket_read(b, &data, &len, APR_BLOCK_READ);

    rv->len = len;
    rv->data = data;
    rv->b = b;
    return rv;
}

static triger_bucket_t *where_to_insert_html_fragment_at_head(ap_filter_t *
							      f)
{
    char c;
    int in_comments = -1;
    apr_size_t i = 0, j = 0;;
    apr_size_t char_counts = 0;
    triger_module_ctx_t *ctx = f->ctx;
    triger_bucket_t *rv = ctx->triger_bucket;
    apr_size_t len = rv->len;
    const char *data = rv->data;
    rv->head_start_tag_pos = rv->body_start_tag_pos = -1;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
		  "Look for <head> and <body>");
    if (len < 1)
	return rv;
    for (; i < len; i++) {
	if (char_counts > rv->limit)
	    return rv;
	else
	    char_counts++;
	c = *(data + i);
	if (in_comments != -1) {
	    switch (c) {
	    case '>':
		if (i >= 2) {
		    if (in_comments == html_comment) {
			if (*(data + i - 1) == '-'
			    && *(data + i - 2) == '-')
			    in_comments = -1;
		    } else if (in_comments == xml_comment) {
			if (*(data + i - 1) == ']'
			    && *(data + i - 2) == ']')
			    in_comments = -1;
		    }
		}
		break;
	    case '<':
		if (in_comments == microsoft_comment)
		    if (i + 9 < len && *(data + i + 1) == '/'
			&& (*(data + i + 2) == 'c'
			    || *(data + i + 2) == 'C')
			&& (*(data + i + 3) == 'o'
			    || *(data + i + 3) == 'O')
			&& (*(data + i + 4) == 'm'
			    || *(data + i + 4) == 'M')
			&& (*(data + i + 5) == 'm'
			    || *(data + i + 5) == 'M')
			&& (*(data + i + 6) == 'e'
			    || *(data + i + 6) == 'E')
			&& (*(data + i + 7) == 'n'
			    || *(data + i + 7) == 'N')
			&& (*(data + i + 8) == 't'
			    || *(data + i + 8) == 'T')
			&& *(data + i + 9) == '>') {
			in_comments = -1;
			i = i + 9;
		    }
		break;
	    default:
		continue;
	    }
	} else {
	    switch (c) {
	    case '<':
		if (i + 14 < len
		    && *(data + i + 1) == '!'
		    && *(data + i + 2) == 'D'
		    && *(data + i + 3) == 'O'
		    && *(data + i + 4) == 'C'
		    && *(data + i + 5) == 'T'
		    && *(data + i + 6) == 'Y'
		    && *(data + i + 7) == 'P'
		    && *(data + i + 8) == 'E'
		    && *(data + i + 9) == ' '
		    && (*(data + i + 10) == 'h' || *(data + i + 10) == 'H')
		    && (*(data + i + 11) == 't' || *(data + i + 11) == 'T')
		    && (*(data + i + 12) == 'm' || *(data + i + 12) == 'M')
		    && (*(data + i + 13) == 'l' || *(data + i + 13) == 'L')
		    && *(data + i + 14) == ' ') {
		    if (!ctx->doctype_tag_find)
			ctx->doctype_tag_find = 1;
		} else if (i + 5 < len
			   && (*(data + i + 1) == 'h'
			       || *(data + i + 1) == 'H')
			   && (*(data + i + 2) == 't'
			       || *(data + i + 2) == 'T')
			   && (*(data + i + 3) == 'm'
			       || *(data + i + 3) == 'M')
			   && (*(data + i + 4) == 'l'
			       || *(data + i + 4) == 'L')
			   && (*(data + i + 5) == '>'
			       || *(data + i + 5) == ' ')) {
		    for (j = i + 5; *(data + j) != '>' && j < len - 1;
			 j++);

		    if (*(data + j) == '>') {
			if (ctx->no_tag_find && !ctx->html_start_tag_find) {
			    ctx->html_start_tag_find = 1;
			    ctx->no_tag_find = 0;
			} else
			    return rv;
			rv->html_start_tag_pos = j;
			i = j;
		    } else
			rv->head_start_tag_pos = -1;
		} else if (i + 5 < len
			   && (*(data + i + 1) == 'h'
			       || *(data + i + 1) == 'H')
			   && (*(data + i + 2) == 'e'
			       || *(data + i + 2) == 'E')
			   && (*(data + i + 3) == 'a'
			       || *(data + i + 3) == 'A')
			   && (*(data + i + 4) == 'd'
			       || *(data + i + 4) == 'D')
			   && (*(data + i + 5) == '>'
			       || *(data + i + 5) == ' ')) {
		    for (j = i + 5; *(data + j) != '>' && j < len - 1;
			 j++);

		    if (*(data + j) == '>') {
			if (!ctx->head_start_tag_find) {
			    ctx->head_start_tag_find = 1;
			    ctx->no_tag_find = 0;
			} else
			    return rv;

			rv->head_start_tag_pos = j;
		    } else
			rv->head_start_tag_pos = -1;
		    return rv;
		} else
		    if (i + 5 < len
			&& (*(data + i + 1) == 'b'
			    || *(data + i + 1) == 'B')
			&& (*(data + i + 2) == 'o'
			    || *(data + i + 2) == 'O')
			&& (*(data + i + 3) == 'd'
			    || *(data + i + 3) == 'D')
			&& (*(data + i + 4) == 'y'
			    || *(data + i + 4) == 'Y')
			&& (*(data + i + 5) == '>'
			    || *(data + i + 5) == ' ')) {
		    for (j = i + 5; *(data + j) != '>' && j < len - 1;
			 j++);

		    if (*(data + j) == '>') {
			if (!ctx->body_start_tag_find) {
			    ctx->body_start_tag_find = 1;
			    ctx->no_tag_find = 0;
			} else
			    return rv;
			rv->body_start_tag_pos = j;
			i = j;
		    } else
			rv->body_start_tag_pos = -1;
		    return rv;
		} else if (i + 3 < len && *(data + i + 1) == '!'
			   && *(data + i + 2) == '-'
			   && *(data + i + 3) == '-') {
		    in_comments = html_comment;
		    i = i + 3;
		} else if (i + 8 < len && *(data + i + 1) == '!'
			   && *(data + i + 2) == '['
			   && *(data + i + 3) == 'C'
			   && *(data + i + 4) == 'D'
			   && *(data + i + 5) == 'A'
			   && *(data + i + 6) == 'T'
			   && *(data + i + 7) == 'A'
			   && *(data + i + 8) == '[') {
		    in_comments = xml_comment;
		    i = i + 8;
		} else if (i + 8 < len
			   && (*(data + i + 1) == 'c'
			       || *(data + i + 1) == 'C')
			   && (*(data + i + 2) == 'o'
			       || *(data + i + 2) == 'O')
			   && (*(data + i + 3) == 'm'
			       || *(data + i + 3) == 'M')
			   && (*(data + i + 4) == 'm'
			       || *(data + i + 4) == 'M')
			   && (*(data + i + 5) == 'e'
			       || *(data + i + 5) == 'E')
			   && (*(data + i + 6) == 'n'
			       || *(data + i + 6) == 'N')
			   && (*(data + i + 7) == 't'
			       || *(data + i + 7) == 'T')
			   && (*(data + i + 8) == '>'
			       || *(data + i + 8) == ' ')) {
		    in_comments = microsoft_comment;
		    i = i + 8;
		} else {
		    ctx->unknown_start_tag_find = 1;
		    return rv;
		}
		break;
	    default:
		continue;
	    }
	}
    }

    return rv;
}

static triger_bucket_t *where_to_insert_html_fragment_at_tail(ap_filter_t *
							      f)
{
    char c;
    apr_size_t i = 0;
    int in_comments = -1;
    triger_module_ctx_t *ctx = f->ctx;
    triger_bucket_t *rv = ctx->triger_bucket;
    apr_size_t j = rv->len;
    apr_size_t len = rv->len;
    apr_size_t char_counts = 0;
    const char *data = rv->data;
    rv->body_end_tag_pos = rv->html_end_tag_pos = -1;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
		  "Look for </body> and </html>");

    for (; j >= 1; j--) {
	i = j - 1;
	if (char_counts > rv->limit)
	    return rv;
	else
	    char_counts++;
	c = *(data + i);
	if (in_comments != -1) {
	    switch (c) {
	    case '<':
		if (in_comments == html_comment) {
		    if (i + 3 < len && *(data + i + 1) == '!'
			&& *(data + i + 2) == '-'
			&& *(data + i + 3) == '-')
			in_comments = -1;
		} else if (in_comments == xml_comment) {
		    if (i + 8 < len && *(data + i + 1) == '!'
			&& *(data + i + 2) == '[' && *(data + i + 3) == 'C'
			&& *(data + i + 4) == 'D' && *(data + i + 5) == 'A'
			&& *(data + i + 6) == 'T' && *(data + i + 7) == 'A'
			&& *(data + i + 8) == '[')
			in_comments = -1;
		} else if (in_comments == microsoft_comment)
		    if (i + 8 < len
			&& (*(data + i + 1) == 'c'
			    || *(data + i + 1) == 'C')
			&& (*(data + i + 2) == 'o'
			    || *(data + i + 2) == 'O')
			&& (*(data + i + 3) == 'm'
			    || *(data + i + 3) == 'M')
			&& (*(data + i + 4) == 'm'
			    || *(data + i + 4) == 'M')
			&& (*(data + i + 5) == 'e'
			    || *(data + i + 5) == 'E')
			&& (*(data + i + 6) == 'n'
			    || *(data + i + 6) == 'N')
			&& (*(data + i + 7) == 't'
			    || *(data + i + 7) == 'T')
			&& *(data + i + 8) == '>')
			in_comments = -1;
		break;
	    default:
		continue;
	    }
	} else {
	    switch (c) {
	    case '<':
		if (i + 6 < len && *(data + i + 1) == '/') {
		    if ((*(data + i + 2) == 'h' || *(data + i + 2) == 'H')
			&& (*(data + i + 3) == 't'
			    || *(data + i + 3) == 'T')
			&& (*(data + i + 4) == 'm'
			    || *(data + i + 4) == 'M')
			&& (*(data + i + 5) == 'l'
			    || *(data + i + 5) == 'L')
			&& *(data + i + 6) == '>') {
			if (!ctx->html_end_tag_find) {
			    ctx->html_end_tag_find = 1;
			    ctx->no_tag_find = 0;
			} else
			    return rv;
			rv->html_end_tag_pos = i;
		    } else if ((*(data + i + 2) == 'b'
				|| *(data + i + 2) == 'B')
			       && (*(data + i + 3) == 'o'
				   || *(data + i + 3) == 'O')
			       && (*(data + i + 4) == 'd'
				   || *(data + i + 4) == 'D')
			       && (*(data + i + 5) == 'y'
				   || *(data + i + 5) == 'Y')
			       && *(data + i + 6) == '>') {
			if (!ctx->body_end_tag_find) {
			    ctx->body_end_tag_find = 1;
			    ctx->no_tag_find = 0;
			} else
			    return rv;
			rv->body_end_tag_pos = i;
			return rv;
		    } else
			if (i + 9 < len
			    && (*(data + i + 2) == 'c'
				|| *(data + i + 2) == 'C')
			    && (*(data + i + 3) == 'o'
				|| *(data + i + 3) == 'O')
			    && (*(data + i + 4) == 'm'
				|| *(data + i + 4) == 'M')
			    && (*(data + i + 5) == 'm'
				|| *(data + i + 5) == 'M')
			    && (*(data + i + 6) == 'e'
				|| *(data + i + 6) == 'E')
			    && (*(data + i + 7) == 'n'
				|| *(data + i + 7) == 'N')
			    && (*(data + i + 8) == 't'
				|| *(data + i + 8) == 'T')
			    && *(data + i + 9) == '>')
			in_comments = microsoft_comment;
		} else {
		    ctx->unknown_end_tag_find = 1;
		    return rv;
		}
		break;
	    case '>':
		if (i >= 2) {
		    if (*(data + i - 1) == '-' && *(data + i - 2) == '-') {
			in_comments = html_comment;
			i = i - 2;
		    } else if (*(data + i - 1) == ']'
			       && *(data + i - 2) == ']') {
			in_comments = xml_comment;
			i = i - 2;
		    }
		}
		break;
	    default:
		continue;
	    }
	}
    }
    return rv;
}

static int
insert_html_fragment_at_head(ap_filter_t * f,
			     apr_bucket_brigade * bb, triger_conf_t * cfg)
{
    triger_module_ctx_t *ctx = f->ctx;
    apr_bucket *tmp_b = ctx->triger_bucket->b;
    int ret = 0;
    apr_size_t pos;
    apr_bucket *js;
    if (ctx->find)
	goto last;
    js = apr_bucket_transient_create(cfg->js, (apr_size_t)
				     strlen(cfg->js) + 1,
				     f->r->connection->bucket_alloc);

    if (!js)
	goto last;
    if (ctx->triger_bucket->head_start_tag_pos != -1) {
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
		      "The <head> tag found, insert at the end: %s",
		      cfg->js);
	pos = ctx->triger_bucket->head_start_tag_pos;
	if (pos + 1 < ctx->triger_bucket->len) {
	    apr_bucket_split(tmp_b, pos + 1);
	    APR_BUCKET_INSERT_AFTER(tmp_b, js);
	} else {
	    APR_BUCKET_INSERT_AFTER(tmp_b, js);
	}
	ctx->find = 1;
    }
  last:
    return ret;
}

static int
insert_html_fragment_at_tail(ap_filter_t * f,
			     apr_bucket_brigade * bb, triger_conf_t * cfg)
{
    apr_bucket *tmp_b;
    int ret = 0;
    apr_size_t pos;
    apr_bucket *js;
    triger_module_ctx_t *ctx = f->ctx;
    if (ctx->find)
	goto last;

    js = apr_bucket_transient_create(cfg->js, (apr_size_t)
				     strlen(cfg->js) + 1,
				     f->r->connection->bucket_alloc);

    if (!js)
	goto last;
    if (ctx->triger_bucket->body_end_tag_pos == -1
	&& ctx->triger_bucket->html_end_tag_pos == -1) {
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
		      "Neither </body> nor </html> tag found, insert at the end: %s",
		      cfg->js);
	tmp_b = APR_BRIGADE_LAST(bb);
	APR_BUCKET_INSERT_BEFORE(tmp_b, js);
    } else {
	tmp_b = ctx->triger_bucket->b;
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
		      "One of </body> and</html> tag are found, insert at there: %s",
		      cfg->js);
	pos =
	    ctx->triger_bucket->body_end_tag_pos !=
	    -1 ? ctx->triger_bucket->body_end_tag_pos : ctx->
	    triger_bucket->html_end_tag_pos;
	apr_bucket_split(tmp_b, pos);
	APR_BUCKET_INSERT_AFTER(tmp_b, js);
    }
    ctx->find = 1;
  last:
    return ret;
}

static apr_status_t triger_filter(ap_filter_t * f, apr_bucket_brigade * bb)
{
    apr_status_t rv = APR_SUCCESS;
    triger_conf_t *cfg;
    apr_bucket *b;
    triger_module_ctx_t *ctx = f->ctx;
    if (APR_BRIGADE_EMPTY(bb))
	return APR_SUCCESS;
    cfg = ap_get_module_config(f->r->per_dir_config, &triger_module);
    if (!cfg)
	goto last;
    if (!cfg->enabled)
	goto last;
    if (!ctx) {
	f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
	if (!ctx)
	    goto last;
	ctx->times = 1;
	ctx->unknown_start_tag_find = 0;
	ctx->unknown_end_tag_find = 0;
	ctx->find = 0;
	ctx->no_tag_find = 1;
	ctx->doctype_tag_find = 0;
	ctx->html_start_tag_find = ctx->head_start_tag_find =
	    ctx->body_start_tag_find = ctx->body_end_tag_find =
	    ctx->html_end_tag_find = 0;
	ctx->triger_bucket =
	    apr_pcalloc(f->r->pool, sizeof(triger_bucket_t));
	if (!ctx->triger_bucket)
	    goto last;
	ctx->triger_bucket->limit = cfg->chk_len;
	ctx->head_check = 0;
	apr_table_unset(f->r->headers_out, "Content-Length");
    } else
	ctx->times++;
    if (!is_this_html(f->r) || ctx->find)
	goto last;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
		  "Enter this filter %u times", ctx->times);
    if (!cfg->full_chk) {
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
		      "Only check the first and last data buckets");
	if (!ctx->head_check) {
	    ctx->head_check = 1;
	    get_data_at_head(f, bb);
	    where_to_insert_html_fragment_at_head(f);
	    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
			  "Find the first data bucket. Content length: %d uri: %s path info: %s positions found: %d (<head>)",
			  (int) ctx->triger_bucket->len, f->r->uri,
			  f->r->path_info,
			  (int) ctx->triger_bucket->head_start_tag_pos);
	    insert_html_fragment_at_head(f, bb, cfg);
	}
	if (ctx->find || !APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb)))
	    goto last;
	get_data_at_tail(f, bb);
	where_to_insert_html_fragment_at_tail(f);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
		      "Find the last data bucket. Content length: %d uri: %s path info: %s positions found: %d (</body>) %d (/html)",
		      (int) ctx->triger_bucket->len, f->r->uri,
		      f->r->path_info,
		      (int) ctx->triger_bucket->body_end_tag_pos,
		      (int) ctx->triger_bucket->html_end_tag_pos);
	insert_html_fragment_at_tail(f, bb, cfg);
    } else {
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, f->r,
		      "Check each data bucket");
	for (b = APR_BRIGADE_FIRST(bb);
	     b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
	    if (!APR_BUCKET_IS_METADATA(b)) {
		get_triger_bucket(f, b);
		where_to_insert_html_fragment_at_head(f);
		insert_html_fragment_at_head(f, bb, cfg);
	    }
	    if (!ctx->find && APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
		get_data_at_tail(f, bb);
		where_to_insert_html_fragment_at_tail(f);
		insert_html_fragment_at_tail(f, bb, cfg);
	    }
	}
    }
  last:
    rv = ap_pass_brigade(f->next, bb);
    return rv;
}

static const char *set_enabled(cmd_parms * cmd, void *mconfig, int on)
{
    triger_conf_t *cfg = mconfig;
    cfg->enabled = on;
    return NULL;
}

static const char *set_inherit(cmd_parms * cmd, void *mconfig, int on)
{
    triger_conf_t *cfg = mconfig;
    cfg->inherit = on;
    return NULL;
}

static const char *set_full_chk(cmd_parms * cmd, void *mconfig, int on)
{
    triger_conf_t *cfg = mconfig;
    cfg->full_chk = on;
    return NULL;
}

static const char *set_js(cmd_parms * cmd, void *mconfig, const char *w)
{
    triger_conf_t *cfg = mconfig;
    if (w)
	cfg->js = apr_pstrdup(cmd->pool, w);
    return NULL;
}

static const char *set_chk_len(cmd_parms * cmd, void *mconfig,
			       const char *w)
{
    triger_conf_t *cfg = mconfig;

    if (w)
	cfg->chk_len = (apr_size_t) atoi(w);
    return NULL;
}

static const char *set_ctypes(cmd_parms * cmd, void *mconf,
			      const char *line)
{
    triger_ctype_t *tmp_ctype;
    apr_pool_t *pool = cmd->pool;
    if (!line)
	return NULL;
    triger_conf_t *cfg = mconf;

    triger_ctype_t *ctype = apr_pcalloc(pool, sizeof(triger_ctype_t));
    if (!ctype)
	return NULL;
    ctype->data = apr_pstrdup(pool, line);
    if (!ctype->data)
	return NULL;
    ctype->prev = ctype->next = NULL;
    if (!cfg->ctypes) {
	cfg->ctypes = ctype;
    } else {
	tmp_ctype = cfg->ctypes->prev;
	if (tmp_ctype) {
	    tmp_ctype->next = ctype;
	    ctype->prev = tmp_ctype;
	    cfg->ctypes->prev = ctype;
	} else {
	    cfg->ctypes->next = ctype;
	    ctype->prev = cfg->ctypes;
	    cfg->ctypes->prev = ctype;
	}
    }
    return NULL;
}

static void register_hooks(apr_pool_t * pool)
{
    ap_register_output_filter(triger_filter_name,
			      triger_filter, NULL, AP_FTYPE_RESOURCE);
}

static const command_rec triger_cmds[] = {
    AP_INIT_FLAG("TrigerEnable",
		 set_enabled,
		 NULL,
		 RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
		 "Enable/Disable the Triger output filter"),
    AP_INIT_FLAG("TrigerInherit",
		 set_inherit,
		 NULL,
		 RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
		 "Inherit main server configurations or not. Only affect TrigerContentType, TrigerHTML, and TrigerCheckLength."),
    AP_INIT_FLAG("TrigerFullCheck",
		 set_full_chk,
		 NULL,
		 RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
		 "Search each data bucket while no more than TrigerCheckLength, default is only check the first and last data buckets."),
    AP_INIT_ITERATE("TrigerContentType",
		    set_ctypes,
		    NULL,
		    RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
		    "Which types response that we will inject our HTML fragment, default are 'text/html' and 'application/xhtml+xml'."),
    AP_INIT_TAKE1("TrigerHTML",
		  set_js,
		  NULL,
		  RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
		  "HTML fragment that Triger will insert into responses bodies after <head> tag or before </body> tag,  or simple at the end if neither tags found."),
    AP_INIT_TAKE1("TrigerCheckLength",
		  set_chk_len,
		  NULL,
		  RSRC_CONF | ACCESS_CONF | OR_FILEINFO,
		  "How long contents we check to find tags so we know where to innsert our js coedes, f.g., <head> and </body>. Default is 256."),
    {
     NULL}
};

module AP_MODULE_DECLARE_DATA triger_module = {
    STANDARD20_MODULE_STUFF,
    create_triger_dir_config,
    merge_triger_dir_config,
    NULL,
    NULL,
    triger_cmds, register_hooks
};
