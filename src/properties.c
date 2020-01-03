/*
 * Copyright (c) 2012 Carsten Munk <carsten.munk@gmail.com>
 *               2008 The Android Open Source Project
 *               2013 Simon Busch <morphis@gravedo.de>
 *               2013 Canonical Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "../include/hybris/properties.h"
#include "properties_p.h"

/* Get/Set a property from the Android Init property socket */
static int send_prop_msg(prop_msg_t *msg,
		void (*propfn)(const char *, const char *, void *),
		void *cookie)
{
	return -1;
}

int property_list(void (*propfn)(const char *key, const char *value, void *cookie), void *cookie)
{
	return -1;
}

static int property_get_socket(const char *key, char *value, const char *default_value)
{
	return -1;
}

int property_get(const char *key, char *value, const char *default_value)
{
	return -1;
}

int property_set(const char *key, const char *value)
{
	return -1;
}

// vim:ts=4:sw=4:noexpandtab
