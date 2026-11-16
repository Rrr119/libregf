/*
 * Library transaction log test program
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
#include <byte_stream.h>
#include <file_stream.h>
#include <memory.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "regf_test_libcerror.h"
#include "regf_test_libregf.h"
#include "regf_test_macros.h"
#include "regf_test_unused.h"

#include "../libregf/libregf_checksum.h"
#include "../libregf/libregf_file.h"
#include "../libregf/libregf_file_header.h"
#include "../libregf/libregf_transaction_log.h"

#define REGF_TEST_TRANSACTION_LOG_HIVE_FILENAME		"regf_test_transaction_log.hive"
#define REGF_TEST_TRANSACTION_LOG_LOG1_FILENAME		"regf_test_transaction_log.hive.LOG1"
#define REGF_TEST_TRANSACTION_LOG_LOG2_FILENAME		"regf_test_transaction_log.hive.LOG2"
#define REGF_TEST_TRANSACTION_LOG_OUTPUT_FILENAME	"regf_test_transaction_log.recovered"

/* Updates a REGF header checksum
 * Returns 1 if successful or -1 on error
 */
int regf_test_transaction_log_update_checksum(
     uint8_t *data,
     libcerror_error_t **error )
{
	uint32_t checksum_value = 0;

	if( libregf_checksum_calculate_little_endian_xor32(
	     &checksum_value,
	     data,
	     508,
	     0,
	     error ) != 1 )
	{
		return( -1 );
	}
	byte_stream_copy_from_uint32_little_endian(
	 &( data[ 508 ] ),
	 checksum_value );

	return( 1 );
}

/* Sets a REGF header
 * Returns 1 if successful or -1 on error
 */
int regf_test_transaction_log_set_header(
     uint8_t *data,
     uint32_t primary_sequence_number,
     uint32_t secondary_sequence_number,
     uint32_t file_type,
     uint32_t hive_bins_size,
     libcerror_error_t **error )
{
	memory_set(
	 data,
	 0,
	 512 );

	memory_copy(
	 data,
	 "regf",
	 4 );

	byte_stream_copy_from_uint32_little_endian(
	 &( data[ 4 ] ),
	 primary_sequence_number );

	byte_stream_copy_from_uint32_little_endian(
	 &( data[ 8 ] ),
	 secondary_sequence_number );

	byte_stream_copy_from_uint64_little_endian(
	 &( data[ 12 ] ),
	 (uint64_t) 0x01d0000000000000UL );

	byte_stream_copy_from_uint32_little_endian(
	 &( data[ 20 ] ),
	 1 );

	byte_stream_copy_from_uint32_little_endian(
	 &( data[ 24 ] ),
	 5 );

	byte_stream_copy_from_uint32_little_endian(
	 &( data[ 28 ] ),
	 file_type );

	byte_stream_copy_from_uint32_little_endian(
	 &( data[ 32 ] ),
	 1 );

	byte_stream_copy_from_uint32_little_endian(
	 &( data[ 40 ] ),
	 hive_bins_size );

	byte_stream_copy_from_uint32_little_endian(
	 &( data[ 44 ] ),
	 1 );

	return( regf_test_transaction_log_update_checksum(
	         data,
	         error ) );
}

/* Creates a minimal hive
 * Returns 1 if successful or -1 on error
 */
int regf_test_transaction_log_create_hive(
     uint8_t **hive_data,
     size_t *hive_data_size,
     uint32_t primary_sequence_number,
     uint32_t secondary_sequence_number,
     libcerror_error_t **error )
{
	if( ( hive_data == NULL )
	 || ( hive_data_size == NULL ) )
	{
		return( -1 );
	}
	*hive_data_size = 8192;
	*hive_data      = (uint8_t *) memory_allocate(
	                               sizeof( uint8_t ) * *hive_data_size );

	if( *hive_data == NULL )
	{
		return( -1 );
	}
	memory_set(
	 *hive_data,
	 0,
	 *hive_data_size );

	if( regf_test_transaction_log_set_header(
	     *hive_data,
	     primary_sequence_number,
	     secondary_sequence_number,
	     LIBREGF_FILE_TYPE_REGISTRY,
	     4096,
	     error ) != 1 )
	{
		return( -1 );
	}
	memory_copy(
	 &( ( *hive_data )[ 4096 ] ),
	 "hbin",
	 4 );

	byte_stream_copy_from_uint32_little_endian(
	 &( ( *hive_data )[ 4100 ] ),
	 0 );

	byte_stream_copy_from_uint32_little_endian(
	 &( ( *hive_data )[ 4104 ] ),
	 4096 );

	return( 1 );
}

/* Creates a DIRT transaction log
 * Returns 1 if successful or -1 on error
 */
int regf_test_transaction_log_create_dirt(
     uint8_t **log_data,
     size_t *log_data_size,
     uint32_t sequence_number,
     uint8_t marker,
     libcerror_error_t **error )
{
	if( ( log_data == NULL )
	 || ( log_data_size == NULL ) )
	{
		return( -1 );
	}
	*log_data_size = 1536;
	*log_data      = (uint8_t *) memory_allocate(
	                              sizeof( uint8_t ) * *log_data_size );

	if( *log_data == NULL )
	{
		return( -1 );
	}
	if( regf_test_transaction_log_set_header(
	     *log_data,
	     sequence_number,
	     sequence_number,
	     LIBREGF_FILE_TYPE_TRANSACTION_LOG1,
	     4096,
	     error ) != 1 )
	{
		return( -1 );
	}
	memory_set(
	 &( ( *log_data )[ 512 ] ),
	 0,
	 1024 );

	memory_copy(
	 &( ( *log_data )[ 512 ] ),
	 "DIRT",
	 4 );

	( *log_data )[ 516 ] = 0x01;

	memory_set(
	 &( ( *log_data )[ 1024 ] ),
	 marker,
	 512 );

	return( 1 );
}

/* Creates an HvLE transaction log
 * Returns 1 if successful or -1 on error
 */
int regf_test_transaction_log_create_hvle(
     uint8_t **log_data,
     size_t *log_data_size,
     uint32_t sequence_number,
     uint32_t page_offset,
     uint8_t marker,
     libcerror_error_t **error )
{
	uint8_t *entry_data   = NULL;
	uint64_t hash_value_1 = 0;
	uint64_t hash_value_2 = 0;

	if( ( log_data == NULL )
	 || ( log_data_size == NULL ) )
	{
		return( -1 );
	}
	*log_data_size = 1536;
	*log_data      = (uint8_t *) memory_allocate(
	                              sizeof( uint8_t ) * *log_data_size );

	if( *log_data == NULL )
	{
		return( -1 );
	}
	if( regf_test_transaction_log_set_header(
	     *log_data,
	     sequence_number,
	     sequence_number,
	     LIBREGF_FILE_TYPE_TRANSACTION_LOG6,
	     4096,
	     error ) != 1 )
	{
		return( -1 );
	}
	memory_set(
	 &( ( *log_data )[ 512 ] ),
	 0,
	 1024 );

	entry_data = &( ( *log_data )[ 512 ] );

	memory_copy(
	 entry_data,
	 "HvLE",
	 4 );

	byte_stream_copy_from_uint32_little_endian(
	 &( entry_data[ 4 ] ),
	 1024 );

	byte_stream_copy_from_uint32_little_endian(
	 &( entry_data[ 12 ] ),
	 sequence_number );

	byte_stream_copy_from_uint32_little_endian(
	 &( entry_data[ 16 ] ),
	 4096 );

	byte_stream_copy_from_uint32_little_endian(
	 &( entry_data[ 20 ] ),
	 1 );

	byte_stream_copy_from_uint32_little_endian(
	 &( entry_data[ 40 ] ),
	 page_offset );

	byte_stream_copy_from_uint32_little_endian(
	 &( entry_data[ 44 ] ),
	 512 );

	memory_set(
	 &( entry_data[ 48 ] ),
	 marker,
	 512 );

	if( libregf_transaction_log_calculate_marvin32(
	     &hash_value_1,
	     &( entry_data[ 40 ] ),
	     984,
	     error ) != 1 )
	{
		return( -1 );
	}
	byte_stream_copy_from_uint64_little_endian(
	 &( entry_data[ 24 ] ),
	 hash_value_1 );

	if( libregf_transaction_log_calculate_marvin32(
	     &hash_value_2,
	     entry_data,
	     32,
	     error ) != 1 )
	{
		return( -1 );
	}
	byte_stream_copy_from_uint64_little_endian(
	 &( entry_data[ 32 ] ),
	 hash_value_2 );

	return( 1 );
}

/* Writes data to a file
 * Returns 1 if successful or -1 on error
 */
int regf_test_transaction_log_write_file(
     const char *filename,
     const uint8_t *data,
     size_t data_size )
{
	FILE *stream = NULL;

	stream = file_stream_open(
	          filename,
	          FILE_STREAM_BINARY_OPEN_WRITE );

	if( stream == NULL )
	{
		return( -1 );
	}
	if( file_stream_write(
	     stream,
	     data,
	     data_size ) != data_size )
	{
		file_stream_close(
		 stream );

		return( -1 );
	}
	file_stream_close(
	 stream );

	return( 1 );
}

/* Reads data from a file
 * Returns read count or -1 on error
 */
ssize_t regf_test_transaction_log_read_file(
         const char *filename,
         uint8_t *data,
         size_t data_size )
{
	FILE *stream      = NULL;
	size_t read_count = 0;

	stream = file_stream_open(
	          filename,
	          FILE_STREAM_BINARY_OPEN_READ );

	if( stream == NULL )
	{
		return( -1 );
	}
	read_count = file_stream_read(
	              stream,
	              data,
	              data_size );

	file_stream_close(
	 stream );

	return( (ssize_t) read_count );
}

/* Tests the Marvin32 hash implementation
 * Returns 1 if successful or 0 if not
 */
int regf_test_transaction_log_marvin32(
     void )
{
	libcerror_error_t *error = NULL;
	uint8_t data[ 40 ];
	uint64_t hash_value      = 0;
	int data_index           = 0;
	int result               = 0;

	for( data_index = 0;
	     data_index < 40;
	     data_index++ )
	{
		data[ data_index ] = (uint8_t) data_index;
	}
	result = libregf_transaction_log_calculate_marvin32(
	          &hash_value,
	          data,
	          40,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	REGF_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	REGF_TEST_ASSERT_EQUAL_UINT64(
	 "hash_value",
	 hash_value,
	 (uint64_t) 0x2366e1bab67b6ea3UL );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	return( 0 );
}

/* Tests DIRT transaction log recovery
 * Returns 1 if successful or 0 if not
 */
int regf_test_transaction_log_recover_dirt(
     void )
{
	libcerror_error_t *error      = NULL;
	libregf_file_header_t *header = NULL;
	uint8_t *hive_data            = NULL;
	size_t hive_data_size         = 0;
	uint8_t *log_data             = NULL;
	size_t log_data_size          = 0;
	uint8_t *recovered_data       = NULL;
	size_t recovered_data_size    = 0;
	uint32_t last_sequence_number = 0;
	int number_of_recovered_pages = 0;
	int result                    = 0;

	result = regf_test_transaction_log_create_hive(
	          &hive_data,
	          &hive_data_size,
	          2,
	          1,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	result = regf_test_transaction_log_create_dirt(
	          &log_data,
	          &log_data_size,
	          2,
	          0xa5,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	result = libregf_transaction_log_recover_data(
	          &recovered_data,
	          &recovered_data_size,
	          &last_sequence_number,
	          &number_of_recovered_pages,
	          hive_data,
	          hive_data_size,
	          log_data,
	          log_data_size,
	          NULL,
	          0,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	REGF_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	REGF_TEST_ASSERT_EQUAL_SIZE(
	 "recovered_data_size",
	 recovered_data_size,
	 (size_t) 8192 );

	REGF_TEST_ASSERT_EQUAL_UINT32(
	 "last_sequence_number",
	 last_sequence_number,
	 (uint32_t) 2 );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "number_of_recovered_pages",
	 number_of_recovered_pages,
	 1 );

	REGF_TEST_ASSERT_EQUAL_UINT8(
	 "recovered_data[ 4096 ]",
	 recovered_data[ 4096 ],
	 (uint8_t) 0xa5 );

	result = libregf_file_header_initialize(
	          &header,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	result = libregf_file_header_read_data(
	          header,
	          recovered_data,
	          512,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	REGF_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	libregf_file_header_free(
	 &header,
	 NULL );
	memory_free(
	 recovered_data );
	memory_free(
	 log_data );
	memory_free(
	 hive_data );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( header != NULL )
	{
		libregf_file_header_free(
		 &header,
		 NULL );
	}
	if( recovered_data != NULL )
	{
		memory_free(
		 recovered_data );
	}
	if( log_data != NULL )
	{
		memory_free(
		 log_data );
	}
	if( hive_data != NULL )
	{
		memory_free(
		 hive_data );
	}
	return( 0 );
}

/* Tests HvLE recovery and sequence chaining
 * Returns 1 if successful or 0 if not
 */
int regf_test_transaction_log_recover_hvle(
     void )
{
	libcerror_error_t *error      = NULL;
	uint8_t *hive_data            = NULL;
	size_t hive_data_size         = 0;
	uint8_t *log1_data            = NULL;
	size_t log1_data_size         = 0;
	uint8_t *log2_data            = NULL;
	size_t log2_data_size         = 0;
	uint8_t *recovered_data       = NULL;
	size_t recovered_data_size    = 0;
	uint32_t last_sequence_number = 0;
	int number_of_recovered_pages = 0;
	int result                    = 0;

	result = regf_test_transaction_log_create_hive(
	          &hive_data,
	          &hive_data_size,
	          4,
	          3,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	result = regf_test_transaction_log_create_hvle(
	          &log1_data,
	          &log1_data_size,
	          4,
	          0,
	          0x5a,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	result = regf_test_transaction_log_create_hvle(
	          &log2_data,
	          &log2_data_size,
	          5,
	          512,
	          0x6b,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	result = libregf_transaction_log_recover_data(
	          &recovered_data,
	          &recovered_data_size,
	          &last_sequence_number,
	          &number_of_recovered_pages,
	          hive_data,
	          hive_data_size,
	          log1_data,
	          log1_data_size,
	          log2_data,
	          log2_data_size,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	REGF_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	REGF_TEST_ASSERT_EQUAL_UINT32(
	 "last_sequence_number",
	 last_sequence_number,
	 (uint32_t) 5 );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "number_of_recovered_pages",
	 number_of_recovered_pages,
	 2 );

	REGF_TEST_ASSERT_EQUAL_UINT8(
	 "recovered_data[ 4096 ]",
	 recovered_data[ 4096 ],
	 (uint8_t) 0x5a );

	REGF_TEST_ASSERT_EQUAL_UINT8(
	 "recovered_data[ 4608 ]",
	 recovered_data[ 4608 ],
	 (uint8_t) 0x6b );

	memory_free(
	 recovered_data );
	recovered_data = NULL;

	memory_free(
	 log2_data );

	result = regf_test_transaction_log_create_hvle(
	          &log2_data,
	          &log2_data_size,
	          6,
	          512,
	          0x6b,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	result = libregf_transaction_log_recover_data(
	          &recovered_data,
	          &recovered_data_size,
	          &last_sequence_number,
	          &number_of_recovered_pages,
	          hive_data,
	          hive_data_size,
	          log1_data,
	          log1_data_size,
	          log2_data,
	          log2_data_size,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	REGF_TEST_ASSERT_EQUAL_UINT32(
	 "last_sequence_number",
	 last_sequence_number,
	 (uint32_t) 4 );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "number_of_recovered_pages",
	 number_of_recovered_pages,
	 1 );

	memory_free(
	 recovered_data );
	memory_free(
	 log2_data );
	memory_free(
	 log1_data );
	memory_free(
	 hive_data );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( recovered_data != NULL )
	{
		memory_free(
		 recovered_data );
	}
	if( log2_data != NULL )
	{
		memory_free(
		 log2_data );
	}
	if( log1_data != NULL )
	{
		memory_free(
		 log1_data );
	}
	if( hive_data != NULL )
	{
		memory_free(
		 hive_data );
	}
	return( 0 );
}

/* Tests that a transaction log with an invalid checksum is ignored
 * Returns 1 if successful or 0 if not
 */
int regf_test_transaction_log_reject_checksum(
     void )
{
	libcerror_error_t *error      = NULL;
	uint8_t *hive_data            = NULL;
	size_t hive_data_size         = 0;
	uint8_t *log_data             = NULL;
	size_t log_data_size          = 0;
	uint8_t *recovered_data       = NULL;
	size_t recovered_data_size    = 0;
	uint32_t last_sequence_number = 0;
	int number_of_recovered_pages = 0;
	int result                    = 0;

	result = regf_test_transaction_log_create_hive(
	          &hive_data,
	          &hive_data_size,
	          2,
	          1,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	result = regf_test_transaction_log_create_dirt(
	          &log_data,
	          &log_data_size,
	          2,
	          0xa5,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	log_data[ 508 ] ^= 0xff;

	result = libregf_transaction_log_recover_data(
	          &recovered_data,
	          &recovered_data_size,
	          &last_sequence_number,
	          &number_of_recovered_pages,
	          hive_data,
	          hive_data_size,
	          log_data,
	          log_data_size,
	          NULL,
	          0,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	REGF_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	REGF_TEST_ASSERT_IS_NULL(
	 "recovered_data",
	 recovered_data );

	memory_free(
	 log_data );
	memory_free(
	 hive_data );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( log_data != NULL )
	{
		memory_free(
		 log_data );
	}
	if( hive_data != NULL )
	{
		memory_free(
		 hive_data );
	}
	return( 0 );
}

/* Tests that an HvLE entry with an invalid hash is ignored
 * Returns 1 if successful or 0 if not
 */
int regf_test_transaction_log_reject_hvle_hash(
     void )
{
	libcerror_error_t *error      = NULL;
	uint8_t *hive_data            = NULL;
	size_t hive_data_size         = 0;
	uint8_t *log_data             = NULL;
	size_t log_data_size          = 0;
	uint8_t *recovered_data       = NULL;
	size_t recovered_data_size    = 0;
	uint32_t last_sequence_number = 0;
	int number_of_recovered_pages = 0;
	int result                    = 0;

	result = regf_test_transaction_log_create_hive(
	          &hive_data,
	          &hive_data_size,
	          4,
	          3,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	result = regf_test_transaction_log_create_hvle(
	          &log_data,
	          &log_data_size,
	          4,
	          0,
	          0x5a,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	log_data[ 560 ] ^= 0xff;

	result = libregf_transaction_log_recover_data(
	          &recovered_data,
	          &recovered_data_size,
	          &last_sequence_number,
	          &number_of_recovered_pages,
	          hive_data,
	          hive_data_size,
	          log_data,
	          log_data_size,
	          NULL,
	          0,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	REGF_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	REGF_TEST_ASSERT_IS_NULL(
	 "recovered_data",
	 recovered_data );

	memory_free(
	 log_data );
	memory_free(
	 hive_data );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( log_data != NULL )
	{
		memory_free(
		 log_data );
	}
	if( hive_data != NULL )
	{
		memory_free(
		 hive_data );
	}
	return( 0 );
}

/* Tests that a clean hive is not modified by a stale transaction log
 * Returns 1 if successful or 0 if not
 */
int regf_test_transaction_log_skip_clean_hive(
     void )
{
	libcerror_error_t *error      = NULL;
	uint8_t *hive_data            = NULL;
	size_t hive_data_size         = 0;
	uint8_t *log_data             = NULL;
	size_t log_data_size          = 0;
	uint8_t *recovered_data       = NULL;
	size_t recovered_data_size    = 0;
	uint32_t last_sequence_number = 0;
	int number_of_recovered_pages = 0;
	int result                    = 0;

	result = regf_test_transaction_log_create_hive(
	          &hive_data,
	          &hive_data_size,
	          2,
	          2,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	result = regf_test_transaction_log_create_dirt(
	          &log_data,
	          &log_data_size,
	          2,
	          0xa5,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	result = libregf_transaction_log_recover_data(
	          &recovered_data,
	          &recovered_data_size,
	          &last_sequence_number,
	          &number_of_recovered_pages,
	          hive_data,
	          hive_data_size,
	          log_data,
	          log_data_size,
	          NULL,
	          0,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	REGF_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	REGF_TEST_ASSERT_IS_NULL(
	 "recovered_data",
	 recovered_data );

	memory_free(
	 log_data );
	memory_free(
	 hive_data );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( log_data != NULL )
	{
		memory_free(
		 log_data );
	}
	if( hive_data != NULL )
	{
		memory_free(
		 hive_data );
	}
	return( 0 );
}

/* Tests automatic transaction log discovery, recovery and output
 * Returns 1 if successful or 0 if not
 */
int regf_test_transaction_log_file_open_and_write(
     void )
{
	uint8_t output_data[ 8192 ];
	libcerror_error_t *error      = NULL;
	libregf_file_t *file          = NULL;
	uint8_t *hive_data            = NULL;
	size_t hive_data_size         = 0;
	uint8_t *log_data             = NULL;
	size_t log_data_size          = 0;
	int is_recovered              = 0;
	int result                    = 0;
	ssize_t read_count            = 0;

	result = regf_test_transaction_log_create_hive(
	          &hive_data,
	          &hive_data_size,
	          2,
	          1,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	result = regf_test_transaction_log_create_dirt(
	          &log_data,
	          &log_data_size,
	          2,
	          0xa5,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	memory_copy(
	 &( log_data[ 1024 ] ),
	 &( hive_data[ 4096 ] ),
	 512 );

	log_data[ 1056 ] = 0xa5;

	result = regf_test_transaction_log_write_file(
	          REGF_TEST_TRANSACTION_LOG_HIVE_FILENAME,
	          hive_data,
	          hive_data_size );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	result = regf_test_transaction_log_write_file(
	          REGF_TEST_TRANSACTION_LOG_LOG1_FILENAME,
	          log_data,
	          log_data_size );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	result = libregf_file_initialize(
	          &file,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	result = libregf_file_open(
	          file,
	          REGF_TEST_TRANSACTION_LOG_HIVE_FILENAME,
	          LIBREGF_OPEN_READ,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	REGF_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libregf_file_is_recovered(
	          file,
	          &is_recovered,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "is_recovered",
	 is_recovered,
	 1 );

	result = libregf_file_write(
	          file,
	          REGF_TEST_TRANSACTION_LOG_OUTPUT_FILENAME,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	read_count = regf_test_transaction_log_read_file(
	              REGF_TEST_TRANSACTION_LOG_OUTPUT_FILENAME,
	              output_data,
	              sizeof( output_data ) );

	REGF_TEST_ASSERT_EQUAL_SSIZE(
	 "read_count",
	 read_count,
	 (ssize_t) sizeof( output_data ) );

	REGF_TEST_ASSERT_EQUAL_UINT8(
	 "output_data[ 4128 ]",
	 output_data[ 4128 ],
	 (uint8_t) 0xa5 );

	result = libregf_file_close(
	          file,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	result = libregf_file_free(
	          &file,
	          &error );

	REGF_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	REGF_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	remove(
	 REGF_TEST_TRANSACTION_LOG_HIVE_FILENAME );
	remove(
	 REGF_TEST_TRANSACTION_LOG_LOG1_FILENAME );
	remove(
	 REGF_TEST_TRANSACTION_LOG_LOG2_FILENAME );
	remove(
	 REGF_TEST_TRANSACTION_LOG_OUTPUT_FILENAME );

	memory_free(
	 log_data );
	memory_free(
	 hive_data );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( file != NULL )
	{
		libregf_file_free(
		 &file,
		 NULL );
	}
	remove(
	 REGF_TEST_TRANSACTION_LOG_HIVE_FILENAME );
	remove(
	 REGF_TEST_TRANSACTION_LOG_LOG1_FILENAME );
	remove(
	 REGF_TEST_TRANSACTION_LOG_LOG2_FILENAME );
	remove(
	 REGF_TEST_TRANSACTION_LOG_OUTPUT_FILENAME );

	if( log_data != NULL )
	{
		memory_free(
		 log_data );
	}
	if( hive_data != NULL )
	{
		memory_free(
		 hive_data );
	}
	return( 0 );
}

/* The main program
 */
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
int wmain(
     int argc REGF_TEST_ATTRIBUTE_UNUSED,
     wchar_t * const argv[] REGF_TEST_ATTRIBUTE_UNUSED )
#else
int main(
     int argc REGF_TEST_ATTRIBUTE_UNUSED,
     char * const argv[] REGF_TEST_ATTRIBUTE_UNUSED )
#endif
{
	REGF_TEST_UNREFERENCED_PARAMETER( argc )
	REGF_TEST_UNREFERENCED_PARAMETER( argv )

	REGF_TEST_RUN(
	 "libregf_transaction_log_marvin32",
	 regf_test_transaction_log_marvin32 );

	REGF_TEST_RUN(
	 "libregf_transaction_log_recover_dirt",
	 regf_test_transaction_log_recover_dirt );

	REGF_TEST_RUN(
	 "libregf_transaction_log_recover_hvle",
	 regf_test_transaction_log_recover_hvle );

	REGF_TEST_RUN(
	 "libregf_transaction_log_reject_checksum",
	 regf_test_transaction_log_reject_checksum );

	REGF_TEST_RUN(
	 "libregf_transaction_log_reject_hvle_hash",
	 regf_test_transaction_log_reject_hvle_hash );

	REGF_TEST_RUN(
	 "libregf_transaction_log_skip_clean_hive",
	 regf_test_transaction_log_skip_clean_hive );

	REGF_TEST_RUN(
	 "libregf_transaction_log_file_open_and_write",
	 regf_test_transaction_log_file_open_and_write );

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

