/*
 * Recovers a Windows NT Registry File (REGF) using transaction logs
 *
 * Copyright (C) 2009-2026, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <common.h>
#include <system_string.h>
#include <types.h>

#include <stdio.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "regftools_getopt.h"
#include "regftools_libcerror.h"
#include "regftools_libclocale.h"
#include "regftools_libcnotify.h"
#include "regftools_libregf.h"
#include "regftools_output.h"
#include "regftools_unused.h"

/* The main program
 */
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
int wmain( int argc, wchar_t * const argv[] )
#else
int main( int argc, char * const argv[] )
#endif
{
	const char *description = \
		"Use regfrecover to apply transaction logs to a Windows NT Registry File (REGF).";

	regftools_option_t options[ ] = {
		{ 'h', NULL, "shows this help" },
		{ 'l', "log1", "the first transaction log" },
		{ 'L', "log2", "the second transaction log" },
		{ 'o', "output", "the output file" },
		{ 'v', NULL, "verbose output to stderr" },
		{ 'V', NULL, "print version" },
		{ 0, "source", "the source file" },
	};
	system_character_t options_string[ 32 ];

	libcerror_error_t *error          = NULL;
	libregf_file_t *file              = NULL;
	system_character_t *option_log1   = NULL;
	system_character_t *option_log2   = NULL;
	system_character_t *option_output = NULL;
	system_character_t *source        = NULL;
	char *program                     = "regfrecover";
	system_integer_t option           = 0;
	int is_recovered                  = 0;
	int number_of_options             = (int) ( sizeof( options ) / sizeof( regftools_option_t ) );
	int result                        = 0;
	int verbose                       = 0;

	libcnotify_stream_set(
	 stderr,
	 NULL );
	libcnotify_verbose_set(
	 1 );

	if( libclocale_initialize(
	     "regftools",
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to initialize locale values.\n" );

		goto on_error;
	}
	if( regftools_output_initialize(
	     _IONBF,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to initialize output settings.\n" );

		goto on_error;
	}
	regftools_output_version_fprint(
	 stdout,
	 program );

	if( regftools_getopt_get_options_string(
	     options,
	     number_of_options,
	     options_string,
	     32 ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to determine options string.\n" );

		goto on_error;
	}
	while( ( option = regftools_getopt(
	                   argc,
	                   argv,
	                   options_string ) ) != (system_integer_t) -1 )
	{
		switch( option )
		{
			case (system_integer_t) '?':
			default:
				fprintf(
				 stderr,
				 "Invalid argument: %" PRIs_SYSTEM "\n",
				 argv[ optind - 1 ] );

				regftools_getopt_usage_fprint(
				 stdout,
				 program,
				 description,
				 options,
				 number_of_options );

				return( EXIT_FAILURE );

			case (system_integer_t) 'h':
				regftools_getopt_usage_fprint(
				 stdout,
				 program,
				 description,
				 options,
				 number_of_options );

				return( EXIT_SUCCESS );

			case (system_integer_t) 'l':
				option_log1 = optarg;

				break;

			case (system_integer_t) 'L':
				option_log2 = optarg;

				break;

			case (system_integer_t) 'o':
				option_output = optarg;

				break;

			case (system_integer_t) 'v':
				verbose = 1;

				break;

			case (system_integer_t) 'V':
				regftools_output_copyright_fprint(
				 stdout );

				return( EXIT_SUCCESS );
		}
	}
	if( optind == argc )
	{
		fprintf(
		 stderr,
		 "Missing source file.\n" );

		regftools_getopt_usage_fprint(
		 stdout,
		 program,
		 description,
		 options,
		 number_of_options );

		return( EXIT_FAILURE );
	}
	source = argv[ optind ];

	if( option_output == NULL )
	{
		fprintf(
		 stderr,
		 "Missing output file.\n" );

		regftools_getopt_usage_fprint(
		 stdout,
		 program,
		 description,
		 options,
		 number_of_options );

		return( EXIT_FAILURE );
	}
	libcnotify_verbose_set(
	 verbose );
	libregf_notify_set_stream(
	 stderr,
	 NULL );
	libregf_notify_set_verbose(
	 verbose );

	if( libregf_file_initialize(
	     &file,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to initialize file.\n" );

		goto on_error;
	}
	if( ( option_log1 != NULL )
	 || ( option_log2 != NULL ) )
	{
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
		result = libregf_file_open_wide_with_transaction_logs(
		          file,
		          source,
		          option_log1,
		          option_log2,
		          LIBREGF_OPEN_READ,
		          &error );
#else
		result = libregf_file_open_with_transaction_logs(
		          file,
		          source,
		          option_log1,
		          option_log2,
		          LIBREGF_OPEN_READ,
		          &error );
#endif
	}
	else
	{
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
		result = libregf_file_open_wide(
		          file,
		          source,
		          LIBREGF_OPEN_READ,
		          &error );
#else
		result = libregf_file_open(
		          file,
		          source,
		          LIBREGF_OPEN_READ,
		          &error );
#endif
	}
	if( result != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to open source file.\n" );

		goto on_error;
	}
	if( libregf_file_is_recovered(
	     file,
	     &is_recovered,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to determine if the file was recovered.\n" );

		goto on_error;
	}
	if( is_recovered == 0 )
	{
		fprintf(
		 stderr,
		 "No transaction log recovery was applied.\n" );
	}
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
	result = libregf_file_write_wide(
	          file,
	          option_output,
	          &error );
#else
	result = libregf_file_write(
	          file,
	          option_output,
	          &error );
#endif
	if( result != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to write recovered hive.\n" );

		goto on_error;
	}
	if( libregf_file_close(
	     file,
	     &error ) != 0 )
	{
		fprintf(
		 stderr,
		 "Unable to close file.\n" );

		goto on_error;
	}
	if( libregf_file_free(
	     &file,
	     &error ) != 1 )
	{
		fprintf(
		 stderr,
		 "Unable to free file.\n" );

		goto on_error;
	}
	return( EXIT_SUCCESS );

on_error:
	if( error != NULL )
	{
		libcnotify_print_error_backtrace(
		 error );
		libcerror_error_free(
		 &error );
	}
	if( file != NULL )
	{
		libregf_file_free(
		 &file,
		 NULL );
	}
	return( EXIT_FAILURE );
}

