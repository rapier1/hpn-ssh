/*
 * Copyright (c) 2025 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the MIT License for more details.
 *
 * You should have received a copy of the MIT License along with this library;
 * if not, see http://opensource.org/licenses/MIT.
 *
 */
/*
 * RFC 8305 Happy Eyeballs Version 2: Better Connectivity Using Concurrency
 *
 * implementation can have a fixed delay for how long to wait before
 * starting the next connection attempt [...] recommended value for a
 * default delay is 250 milliseconds.
 */

int happy_eyeballs(const char *, struct addrinfo *,
		   struct sockaddr_storage *, int *);



