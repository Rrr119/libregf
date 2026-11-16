/*
 * Transaction log functions
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
#include <memory.h>
#include <types.h>

#include "libregf_checksum.h"
#include "libregf_libbfio.h"
#include "libregf_libcerror.h"
#include "libregf_transaction_log.h"

#define LIBREGF_TRANSACTION_LOG_HEADER_SIZE		512
#define LIBREGF_TRANSACTION_LOG_HVLE_HEADER_SIZE		40
#define LIBREGF_TRANSACTION_LOG_HIVE_BIN_SIZE		4096

#define LIBREGF_TRANSACTION_LOG_FORMAT_UNKNOWN		0
#define LIBREGF_TRANSACTION_LOG_FORMAT_DIRT		1
#define LIBREGF_TRANSACTION_LOG_FORMAT_HVLE		2

#define LIBREGF_TRANSACTION_LOG_FILE_TYPE_PRIMARY	0
#define LIBREGF_TRANSACTION_LOG_FILE_TYPE_DIRT		1
#define LIBREGF_TRANSACTION_LOG_FILE_TYPE_DIRT_2000	2
#define LIBREGF_TRANSACTION_LOG_FILE_TYPE_HVLE		6

#define LIBREGF_TRANSACTION_LOG_MARVIN32_SEED_LOW	0x7a4e55c5UL
#define LIBREGF_TRANSACTION_LOG_MARVIN32_SEED_HIGH	0x82ef4d88UL

typedef struct libregf_transaction_log_header libregf_transaction_log_header_t;
typedef struct libregf_transaction_log_entry libregf_transaction_log_entry_t;
typedef struct libregf_transaction_log libregf_transaction_log_t;

struct libregf_transaction_log_header
{
	uint32_t primary_sequence_number;
	uint32_t secondary_sequence_number;
	uint64_t modification_time;
	uint32_t file_type;
	uint32_t hive_bins_size;
	uint32_t flags;
	uint8_t signature_is_valid;
	uint8_t checksum_is_valid;
};

struct libregf_transaction_log_entry
{
	uint32_t sequence_number;
	uint32_t hive_bins_size;
	uint32_t flags;
	uint32_t number_of_dirty_pages;
	uint32_t size;
	size_t file_offset;
	size_t dirty_page_references_offset;
	size_t dirty_page_data_offset;
};

struct libregf_transaction_log
{
	const uint8_t *data;
	size_t data_size;
	int format;
	libregf_transaction_log_header_t header;
	libregf_transaction_log_entry_t *entries;
	size_t number_of_entries;
};

int libregf_transaction_log_read_header(
     libregf_transaction_log_header_t *header,
     const uint8_t *data,
     size_t data_size,
     libcerror_error_t **error );

int libregf_transaction_log_parse_hvle_entries(
     libregf_transaction_log_t *transaction_log,
     libcerror_error_t **error );

int libregf_transaction_log_parse(
     libregf_transaction_log_t *transaction_log,
     const uint8_t *data,
     size_t data_size,
     libcerror_error_t **error );

int libregf_transaction_log_free(
     libregf_transaction_log_t *transaction_log,
     libcerror_error_t **error );

int libregf_transaction_log_resize_recovered_data(
     uint8_t **recovered_data,
     size_t *recovered_data_size,
     size_t required_size,
     libcerror_error_t **error );

int libregf_transaction_log_update_header(
     uint8_t *data,
     size_t data_size,
     uint32_t sequence_number,
     uint32_t hive_bins_size,
     uint8_t has_flags,
     uint32_t flags,
     libcerror_error_t **error );

int libregf_transaction_log_sequence_is_before(
     uint32_t sequence_number_1,
     uint32_t sequence_number_2 );

int libregf_transaction_log_apply_dirt(
     libregf_transaction_log_t *transaction_logs,
     int number_of_transaction_logs,
     const uint8_t *hive_data,
     size_t hive_data_size,
     const libregf_transaction_log_header_t *hive_header,
     uint8_t **recovered_data,
     size_t *recovered_data_size,
     uint32_t *last_sequence_number,
     int *number_of_recovered_pages,
     libcerror_error_t **error );

int libregf_transaction_log_apply_hvle(
     libregf_transaction_log_t *transaction_logs,
     int number_of_transaction_logs,
     const uint8_t *hive_data,
     size_t hive_data_size,
     const libregf_transaction_log_header_t *hive_header,
     uint8_t **recovered_data,
     size_t *recovered_data_size,
     uint32_t *last_sequence_number,
     int *number_of_recovered_pages,
     libcerror_error_t **error );

/* Calculates the Marvin32 hash
 * Returns 1 if successful or -1 on error
 */
int libregf_transaction_log_calculate_marvin32(
     uint64_t *hash_value,
     const uint8_t *data,
     size_t data_size,
     libcerror_error_t **error )
{
	static char *function = "libregf_transaction_log_calculate_marvin32";
	size_t data_offset    = 0;
	size_t remaining_size = 0;
	uint32_t high_value   = 0;
	uint32_t low_value    = 0;
	uint32_t value_32bit  = 0;

	if( hash_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid hash value.",
		 function );

		return( -1 );
	}
	if( data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid data.",
		 function );

		return( -1 );
	}
	if( data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	low_value  = LIBREGF_TRANSACTION_LOG_MARVIN32_SEED_LOW;
	high_value = LIBREGF_TRANSACTION_LOG_MARVIN32_SEED_HIGH;

	while( ( data_size - data_offset ) >= 4 )
	{
		byte_stream_copy_to_uint32_little_endian(
		 &( data[ data_offset ] ),
		 value_32bit );

		low_value += value_32bit;
		high_value ^= low_value;

		low_value  = ( ( low_value << 20 ) | ( low_value >> 12 ) ) + high_value;
		high_value = ( ( high_value << 9 ) | ( high_value >> 23 ) ) ^ low_value;
		low_value  = ( ( low_value << 27 ) | ( low_value >> 5 ) ) + high_value;
		high_value = ( high_value << 19 ) | ( high_value >> 13 );

		data_offset += 4;
	}
	remaining_size = data_size - data_offset;
	value_32bit    = 0x80;

	if( remaining_size == 3 )
	{
		value_32bit = ( value_32bit << 8 ) | data[ data_offset + 2 ];
		value_32bit = ( value_32bit << 8 ) | data[ data_offset + 1 ];
		value_32bit = ( value_32bit << 8 ) | data[ data_offset ];
	}
	else if( remaining_size == 2 )
	{
		value_32bit = ( value_32bit << 8 ) | data[ data_offset + 1 ];
		value_32bit = ( value_32bit << 8 ) | data[ data_offset ];
	}
	else if( remaining_size == 1 )
	{
		value_32bit = ( value_32bit << 8 ) | data[ data_offset ];
	}
	low_value += value_32bit;
	high_value ^= low_value;

	low_value  = ( ( low_value << 20 ) | ( low_value >> 12 ) ) + high_value;
	high_value = ( ( high_value << 9 ) | ( high_value >> 23 ) ) ^ low_value;
	low_value  = ( ( low_value << 27 ) | ( low_value >> 5 ) ) + high_value;
	high_value = ( high_value << 19 ) | ( high_value >> 13 );

	low_value += 0;
	high_value ^= low_value;

	low_value  = ( ( low_value << 20 ) | ( low_value >> 12 ) ) + high_value;
	high_value = ( ( high_value << 9 ) | ( high_value >> 23 ) ) ^ low_value;
	low_value  = ( ( low_value << 27 ) | ( low_value >> 5 ) ) + high_value;
	high_value = ( high_value << 19 ) | ( high_value >> 13 );

	*hash_value = ( (uint64_t) high_value << 32 ) | low_value;

	return( 1 );
}

/* Reads a transaction log or hive header
 * Returns 1 if successful or -1 on error
 */
int libregf_transaction_log_read_header(
     libregf_transaction_log_header_t *header,
     const uint8_t *data,
     size_t data_size,
     libcerror_error_t **error )
{
	static char *function              = "libregf_transaction_log_read_header";
	uint32_t calculated_xor32_checksum = 0;
	uint32_t stored_xor32_checksum     = 0;

	if( header == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid header.",
		 function );

		return( -1 );
	}
	if( data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid data.",
		 function );

		return( -1 );
	}
	if( data_size < LIBREGF_TRANSACTION_LOG_HEADER_SIZE )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid data size value out of bounds.",
		 function );

		return( -1 );
	}
	memory_set(
	 header,
	 0,
	 sizeof( libregf_transaction_log_header_t ) );

	header->signature_is_valid = ( memory_compare(
	                                data,
	                                "regf",
	                                4 ) == 0 );

	byte_stream_copy_to_uint32_little_endian(
	 &( data[ 4 ] ),
	 header->primary_sequence_number );

	byte_stream_copy_to_uint32_little_endian(
	 &( data[ 8 ] ),
	 header->secondary_sequence_number );

	byte_stream_copy_to_uint64_little_endian(
	 &( data[ 12 ] ),
	 header->modification_time );

	byte_stream_copy_to_uint32_little_endian(
	 &( data[ 28 ] ),
	 header->file_type );

	byte_stream_copy_to_uint32_little_endian(
	 &( data[ 40 ] ),
	 header->hive_bins_size );

	byte_stream_copy_to_uint32_little_endian(
	 &( data[ 144 ] ),
	 header->flags );

	if( libregf_checksum_calculate_little_endian_xor32(
	     &calculated_xor32_checksum,
	     data,
	     508,
	     0,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to calculate XOR-32 checksum.",
		 function );

		return( -1 );
	}
	byte_stream_copy_to_uint32_little_endian(
	 &( data[ 508 ] ),
	 stored_xor32_checksum );

	header->checksum_is_valid = ( stored_xor32_checksum == calculated_xor32_checksum );

	return( 1 );
}

/* Parses HvLE log entries
 * Returns 1 if successful or -1 on error
 */
int libregf_transaction_log_parse_hvle_entries(
     libregf_transaction_log_t *transaction_log,
     libcerror_error_t **error )
{
	libregf_transaction_log_entry_t *entry = NULL;
	static char *function                  = "libregf_transaction_log_parse_hvle_entries";
	uint64_t calculated_hash_1             = 0;
	uint64_t calculated_hash_2             = 0;
	uint64_t dirty_pages_data_size         = 0;
	uint64_t stored_hash_1                 = 0;
	uint64_t stored_hash_2                 = 0;
	size_t entry_offset                    = 0;
	size_t maximum_number_of_entries       = 0;
	uint32_t entry_size                    = 0;
	uint32_t number_of_dirty_pages         = 0;
	uint32_t page_index                    = 0;
	uint32_t page_offset                   = 0;
	uint32_t page_size                     = 0;
	uint32_t value_32bit                   = 0;

	if( transaction_log == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid transaction log.",
		 function );

		return( -1 );
	}
	if( transaction_log->data_size <= LIBREGF_TRANSACTION_LOG_HEADER_SIZE )
	{
		return( 1 );
	}
	maximum_number_of_entries = ( transaction_log->data_size - LIBREGF_TRANSACTION_LOG_HEADER_SIZE ) / 512;

	if( maximum_number_of_entries == 0 )
	{
		return( 1 );
	}
	if( maximum_number_of_entries > ( MEMORY_MAXIMUM_ALLOCATION_SIZE / sizeof( libregf_transaction_log_entry_t ) ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid maximum number of entries value exceeds maximum.",
		 function );

		return( -1 );
	}
	transaction_log->entries = (libregf_transaction_log_entry_t *) memory_allocate(
	                                                               sizeof( libregf_transaction_log_entry_t ) * maximum_number_of_entries );

	if( transaction_log->entries == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create log entries.",
		 function );

		return( -1 );
	}
	entry_offset = LIBREGF_TRANSACTION_LOG_HEADER_SIZE;

	while( ( entry_offset + LIBREGF_TRANSACTION_LOG_HVLE_HEADER_SIZE ) <= transaction_log->data_size )
	{
		if( memory_compare(
		     &( transaction_log->data[ entry_offset ] ),
		     "HvLE",
		     4 ) != 0 )
		{
			break;
		}
		byte_stream_copy_to_uint32_little_endian(
		 &( transaction_log->data[ entry_offset + 4 ] ),
		 entry_size );

		if( ( entry_size < 512 )
		 || ( ( entry_size % 512 ) != 0 )
		 || ( (size_t) entry_size > ( transaction_log->data_size - entry_offset ) ) )
		{
			break;
		}
		byte_stream_copy_to_uint32_little_endian(
		 &( transaction_log->data[ entry_offset + 20 ] ),
		 number_of_dirty_pages );

		if( ( (uint64_t) number_of_dirty_pages * 8 ) > ( entry_size - LIBREGF_TRANSACTION_LOG_HVLE_HEADER_SIZE ) )
		{
			break;
		}
		byte_stream_copy_to_uint32_little_endian(
		 &( transaction_log->data[ entry_offset + 16 ] ),
		 value_32bit );

		/* The hive bins data size can only grow in multiples of 4096.
		 */
		if( ( value_32bit < LIBREGF_TRANSACTION_LOG_HIVE_BIN_SIZE )
		 || ( ( value_32bit % LIBREGF_TRANSACTION_LOG_HIVE_BIN_SIZE ) != 0 ) )
		{
			break;
		}
		if( libregf_transaction_log_calculate_marvin32(
		     &calculated_hash_1,
		     &( transaction_log->data[ entry_offset + LIBREGF_TRANSACTION_LOG_HVLE_HEADER_SIZE ] ),
		     entry_size - LIBREGF_TRANSACTION_LOG_HVLE_HEADER_SIZE,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to calculate hash-1.",
			 function );

			return( -1 );
		}
		if( libregf_transaction_log_calculate_marvin32(
		     &calculated_hash_2,
		     &( transaction_log->data[ entry_offset ] ),
		     32,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
			 "%s: unable to calculate hash-2.",
			 function );

			return( -1 );
		}
		byte_stream_copy_to_uint64_little_endian(
		 &( transaction_log->data[ entry_offset + 24 ] ),
		 stored_hash_1 );

		byte_stream_copy_to_uint64_little_endian(
		 &( transaction_log->data[ entry_offset + 32 ] ),
		 stored_hash_2 );

		if( ( stored_hash_1 != calculated_hash_1 )
		 || ( stored_hash_2 != calculated_hash_2 ) )
		{
			break;
		}
		dirty_pages_data_size = 0;

		for( page_index = 0;
		     page_index < number_of_dirty_pages;
		     page_index++ )
		{
			byte_stream_copy_to_uint32_little_endian(
			 &( transaction_log->data[ entry_offset + LIBREGF_TRANSACTION_LOG_HVLE_HEADER_SIZE + ( page_index * 8 ) ] ),
			 page_offset );

			byte_stream_copy_to_uint32_little_endian(
			 &( transaction_log->data[ entry_offset + LIBREGF_TRANSACTION_LOG_HVLE_HEADER_SIZE + ( page_index * 8 ) + 4 ] ),
			 page_size );

			if( ( page_size == 0 )
			 || ( ( (uint64_t) page_offset + page_size ) > value_32bit ) )
			{
				break;
			}
			dirty_pages_data_size += page_size;
		}
		if( page_index < number_of_dirty_pages )
		{
			break;
		}
		if( dirty_pages_data_size > ( entry_size - LIBREGF_TRANSACTION_LOG_HVLE_HEADER_SIZE - ( (uint64_t) number_of_dirty_pages * 8 ) ) )
		{
			break;
		}
		entry = &( transaction_log->entries[ transaction_log->number_of_entries ] );

		byte_stream_copy_to_uint32_little_endian(
		 &( transaction_log->data[ entry_offset + 8 ] ),
		 entry->flags );

		byte_stream_copy_to_uint32_little_endian(
		 &( transaction_log->data[ entry_offset + 12 ] ),
		 entry->sequence_number );

		entry->hive_bins_size                  = value_32bit;
		entry->number_of_dirty_pages          = number_of_dirty_pages;
		entry->size                           = entry_size;
		entry->file_offset                    = entry_offset;
		entry->dirty_page_references_offset   = entry_offset + LIBREGF_TRANSACTION_LOG_HVLE_HEADER_SIZE;
		entry->dirty_page_data_offset         = entry->dirty_page_references_offset + ( number_of_dirty_pages * 8 );

		transaction_log->number_of_entries++;
		entry_offset += entry_size;
	}
	return( 1 );
}

/* Parses a transaction log
 * Returns 1 if successful or -1 on error
 */
int libregf_transaction_log_parse(
     libregf_transaction_log_t *transaction_log,
     const uint8_t *data,
     size_t data_size,
     libcerror_error_t **error )
{
	static char *function = "libregf_transaction_log_parse";

	if( transaction_log == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid transaction log.",
		 function );

		return( -1 );
	}
	if( data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid data.",
		 function );

		return( -1 );
	}
	memory_set(
	 transaction_log,
	 0,
	 sizeof( libregf_transaction_log_t ) );

	transaction_log->data      = data;
	transaction_log->data_size = data_size;

	if( data_size < LIBREGF_TRANSACTION_LOG_HEADER_SIZE )
	{
		return( 1 );
	}
	if( libregf_transaction_log_read_header(
	     &( transaction_log->header ),
	     data,
	     data_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_READ_FAILED,
		 "%s: unable to read transaction log header.",
		 function );

		return( -1 );
	}
	if( transaction_log->header.signature_is_valid == 0 )
	{
		return( 1 );
	}
	switch( transaction_log->header.file_type )
	{
		case LIBREGF_TRANSACTION_LOG_FILE_TYPE_DIRT:
		case LIBREGF_TRANSACTION_LOG_FILE_TYPE_DIRT_2000:
			transaction_log->format = LIBREGF_TRANSACTION_LOG_FORMAT_DIRT;
			break;

		case LIBREGF_TRANSACTION_LOG_FILE_TYPE_HVLE:
			transaction_log->format = LIBREGF_TRANSACTION_LOG_FORMAT_HVLE;
			break;

		default:
			break;
	}
	if( ( transaction_log->format == LIBREGF_TRANSACTION_LOG_FORMAT_HVLE )
	 && ( transaction_log->header.checksum_is_valid != 0 ) )
	{
		if( libregf_transaction_log_parse_hvle_entries(
		     transaction_log,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_READ_FAILED,
			 "%s: unable to parse HvLE log entries.",
			 function );

			return( -1 );
		}
	}
	return( 1 );
}

/* Frees a parsed transaction log
 * Returns 1 if successful or -1 on error
 */
int libregf_transaction_log_free(
     libregf_transaction_log_t *transaction_log,
     libcerror_error_t **error )
{
	static char *function = "libregf_transaction_log_free";

	if( transaction_log == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid transaction log.",
		 function );

		return( -1 );
	}
	if( transaction_log->entries != NULL )
	{
		memory_free(
		 transaction_log->entries );

		transaction_log->entries = NULL;
	}
	transaction_log->number_of_entries = 0;

	return( 1 );
}

/* Resizes recovered hive data
 * Returns 1 if successful or -1 on error
 */
int libregf_transaction_log_resize_recovered_data(
     uint8_t **recovered_data,
     size_t *recovered_data_size,
     size_t required_size,
     libcerror_error_t **error )
{
	uint8_t *data    = NULL;
	size_t data_size = 0;
	static char *function = "libregf_transaction_log_resize_recovered_data";

	if( recovered_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid recovered data.",
		 function );

		return( -1 );
	}
	if( recovered_data_size == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid recovered data size.",
		 function );

		return( -1 );
	}
	if( required_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid required size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( required_size <= *recovered_data_size )
	{
		return( 1 );
	}
	data      = *recovered_data;
	data_size = *recovered_data_size;

	if( data == NULL )
	{
		data = (uint8_t *) memory_allocate(
		                    sizeof( uint8_t ) * required_size );
	}
	else
	{
		data = (uint8_t *) memory_reallocate(
		                    data,
		                    sizeof( uint8_t ) * required_size );
	}
	if( data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to resize recovered data.",
		 function );

		return( -1 );
	}
	memory_set(
	 &( data[ data_size ] ),
	 0,
	 required_size - data_size );

	*recovered_data      = data;
	*recovered_data_size = required_size;

	return( 1 );
}

/* Updates the checksum of a hive header
 * Returns 1 if successful or -1 on error
 */
int libregf_transaction_log_update_header_checksum(
     uint8_t *data,
     size_t data_size,
     libcerror_error_t **error )
{
	static char *function   = "libregf_transaction_log_update_header_checksum";
	uint32_t checksum_value = 0;

	if( ( data == NULL )
	 || ( data_size < LIBREGF_TRANSACTION_LOG_HEADER_SIZE ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid data.",
		 function );

		return( -1 );
	}
	if( libregf_checksum_calculate_little_endian_xor32(
	     &checksum_value,
	     data,
	     508,
	     0,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to calculate XOR-32 checksum.",
		 function );

		return( -1 );
	}
	byte_stream_copy_from_uint32_little_endian(
	 &( data[ 508 ] ),
	 checksum_value );

	return( 1 );
}

/* Updates a recovered hive header
 * Returns 1 if successful or -1 on error
 */
int libregf_transaction_log_update_header(
     uint8_t *data,
     size_t data_size,
     uint32_t sequence_number,
     uint32_t hive_bins_size,
     uint8_t has_flags,
     uint32_t flags,
     libcerror_error_t **error )
{
	static char *function = "libregf_transaction_log_update_header";
	uint32_t value_32bit  = 0;

	if( ( data == NULL )
	 || ( data_size < LIBREGF_TRANSACTION_LOG_HEADER_SIZE ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid data.",
		 function );

		return( -1 );
	}
	memory_copy(
	 data,
	 "regf",
	 4 );

	byte_stream_copy_from_uint32_little_endian(
	 &( data[ 4 ] ),
	 sequence_number );

	byte_stream_copy_from_uint32_little_endian(
	 &( data[ 8 ] ),
	 sequence_number );

	byte_stream_copy_from_uint32_little_endian(
	 &( data[ 28 ] ),
	 LIBREGF_TRANSACTION_LOG_FILE_TYPE_PRIMARY );

	byte_stream_copy_from_uint32_little_endian(
	 &( data[ 40 ] ),
	 hive_bins_size );

	if( has_flags != 0 )
	{
		byte_stream_copy_to_uint32_little_endian(
		 &( data[ 144 ] ),
		 value_32bit );

		if( ( flags & 0x00000001UL ) != 0 )
		{
			value_32bit |= 0x00000001UL;
		}
		else
		{
			value_32bit &= ~( 0x00000001UL );
		}
		byte_stream_copy_from_uint32_little_endian(
		 &( data[ 144 ] ),
		 value_32bit );
	}
	return( libregf_transaction_log_update_header_checksum(
	         data,
	         data_size,
	         error ) );
}

/* Determines if the first sequence number is before the second
 * Returns 1 if true, 0 if not
 */
int libregf_transaction_log_sequence_is_before(
     uint32_t sequence_number_1,
     uint32_t sequence_number_2 )
{
	if( sequence_number_1 == sequence_number_2 )
	{
		return( 0 );
	}
	return( ( (int32_t) ( sequence_number_2 - sequence_number_1 ) > 0 ) );
}

/* Applies a DIRT transaction log
 * Returns 1 if successful, 0 if no recovery was possible or -1 on error
 */
int libregf_transaction_log_apply_dirt(
     libregf_transaction_log_t *transaction_logs,
     int number_of_transaction_logs,
     const uint8_t *hive_data,
     size_t hive_data_size,
     const libregf_transaction_log_header_t *hive_header,
     uint8_t **recovered_data,
     size_t *recovered_data_size,
     uint32_t *last_sequence_number,
     int *number_of_recovered_pages,
     libcerror_error_t **error )
{
	const uint8_t *bitmap              = NULL;
	libregf_transaction_log_t *log     = NULL;
	libregf_transaction_log_t *selected_log = NULL;
	static char *function              = "libregf_transaction_log_apply_dirt";
	uint64_t required_size             = 0;
	size_t bitmap_size                 = 0;
	size_t data_offset                 = 0;
	size_t page_count                  = 0;
	size_t page_index                  = 0;
	size_t required_pages_size         = 0;
	uint32_t bit_index                 = 0;
	uint32_t number_of_bits            = 0;
	int log_index                      = 0;

	if( ( transaction_logs == NULL )
	 || ( hive_data == NULL )
	 || ( hive_header == NULL )
	 || ( recovered_data == NULL )
	 || ( recovered_data_size == NULL )
	 || ( last_sequence_number == NULL )
	 || ( number_of_recovered_pages == NULL ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid argument.",
		 function );

		return( -1 );
	}
	for( log_index = 0;
	     log_index < number_of_transaction_logs;
	     log_index++ )
	{
		log = &( transaction_logs[ log_index ] );

		if( ( log->format != LIBREGF_TRANSACTION_LOG_FORMAT_DIRT )
		 || ( log->header.signature_is_valid == 0 )
		 || ( log->header.checksum_is_valid == 0 )
		 || ( log->header.primary_sequence_number != log->header.secondary_sequence_number )
		 || ( log->header.hive_bins_size == 0 )
		 || ( ( log->header.hive_bins_size % 512 ) != 0 ) )
		{
			continue;
		}
		if( ( hive_header->checksum_is_valid != 0 )
		 && ( hive_header->modification_time != 0 )
		 && ( log->header.modification_time < hive_header->modification_time ) )
		{
			continue;
		}
		if( ( log->data_size < ( LIBREGF_TRANSACTION_LOG_HEADER_SIZE + 4 ) )
		 || ( memory_compare(
		       &( log->data[ LIBREGF_TRANSACTION_LOG_HEADER_SIZE ] ),
		       "DIRT",
		       4 ) != 0 ) )
		{
			continue;
		}
		number_of_bits = ( log->header.hive_bins_size + 511 ) / 512;
		bitmap_size    = ( number_of_bits + 7 ) / 8;

		if( bitmap_size > ( log->data_size - LIBREGF_TRANSACTION_LOG_HEADER_SIZE - 4 ) )
		{
			continue;
		}
		bitmap = &( log->data[ LIBREGF_TRANSACTION_LOG_HEADER_SIZE + 4 ] );
		page_count = 0;

		for( bit_index = 0;
		     bit_index < number_of_bits;
		     bit_index++ )
		{
			if( ( bitmap[ bit_index / 8 ] & ( 1 << ( bit_index % 8 ) ) ) != 0 )
			{
				page_count++;
			}
		}
		data_offset = LIBREGF_TRANSACTION_LOG_HEADER_SIZE + 4 + bitmap_size;

		if( ( data_offset % 512 ) != 0 )
		{
			data_offset = ( ( data_offset / 512 ) + 1 ) * 512;
		}
		required_pages_size = page_count * 512;

		if( ( data_offset > log->data_size )
		 || ( required_pages_size > ( log->data_size - data_offset ) ) )
		{
			continue;
		}
		if( selected_log == NULL )
		{
			selected_log = log;
		}
		else if( ( log->header.modification_time > selected_log->header.modification_time )
		      || ( ( log->header.modification_time == selected_log->header.modification_time )
		       && ( libregf_transaction_log_sequence_is_before(
		            selected_log->header.primary_sequence_number,
		            log->header.primary_sequence_number ) != 0 ) )
		      || ( ( log->header.modification_time == selected_log->header.modification_time )
		       && ( log->header.primary_sequence_number == selected_log->header.primary_sequence_number )
		       && ( log_index > 0 ) ) )
		{
			selected_log = log;
		}
	}
	if( selected_log == NULL )
	{
		return( 0 );
	}
	number_of_bits      = ( selected_log->header.hive_bins_size + 511 ) / 512;
	bitmap_size         = ( number_of_bits + 7 ) / 8;
	bitmap              = &( selected_log->data[ LIBREGF_TRANSACTION_LOG_HEADER_SIZE + 4 ] );
	data_offset         = LIBREGF_TRANSACTION_LOG_HEADER_SIZE + 4 + bitmap_size;
	required_pages_size = 0;

	if( ( data_offset % 512 ) != 0 )
	{
		data_offset = ( ( data_offset / 512 ) + 1 ) * 512;
	}
	for( bit_index = 0;
	     bit_index < number_of_bits;
	     bit_index++ )
	{
		if( ( bitmap[ bit_index / 8 ] & ( 1 << ( bit_index % 8 ) ) ) != 0 )
		{
			required_pages_size += 512;
		}
	}
	required_size = (uint64_t) LIBREGF_TRANSACTION_LOG_HIVE_BIN_SIZE + selected_log->header.hive_bins_size;

	if( required_size > (uint64_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid recovered data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( libregf_transaction_log_resize_recovered_data(
	     recovered_data,
	     recovered_data_size,
	     (size_t) required_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to resize recovered data.",
		 function );

		return( -1 );
	}
	if( hive_data_size < *recovered_data_size )
	{
		memory_copy(
		 *recovered_data,
		 hive_data,
		 hive_data_size );
	}
	else
	{
		memory_copy(
		 *recovered_data,
		 hive_data,
		 *recovered_data_size );
	}
	if( hive_header->checksum_is_valid == 0 )
	{
		memory_copy(
		 *recovered_data,
		 selected_log->data,
		 LIBREGF_TRANSACTION_LOG_HEADER_SIZE );
	}
	page_index = 0;

	for( bit_index = 0;
	     bit_index < number_of_bits;
	     bit_index++ )
	{
		if( ( bitmap[ bit_index / 8 ] & ( 1 << ( bit_index % 8 ) ) ) == 0 )
		{
			continue;
		}
		memory_copy(
		 &( ( *recovered_data )[ LIBREGF_TRANSACTION_LOG_HIVE_BIN_SIZE + ( bit_index * 512 ) ] ),
		 &( selected_log->data[ data_offset + ( page_index * 512 ) ] ),
		 512 );

		page_index++;
	}
	if( libregf_transaction_log_update_header(
	     *recovered_data,
	     *recovered_data_size,
	     selected_log->header.primary_sequence_number,
	     selected_log->header.hive_bins_size,
	     0,
	     0,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to update recovered hive header.",
		 function );

		return( -1 );
	}
	*last_sequence_number     = selected_log->header.primary_sequence_number;
	*number_of_recovered_pages = (int) page_index;

	return( 1 );
}

/* Selects a continuous chain of HvLE log entries
 * Returns 1 if successful or -1 on error
 */
int libregf_transaction_log_select_hvle_entries(
     libregf_transaction_log_t *transaction_logs,
     int number_of_transaction_logs,
     const libregf_transaction_log_header_t *hive_header,
     libregf_transaction_log_entry_t ***selected_entries,
     libregf_transaction_log_t ***selected_logs,
     size_t *number_of_selected_entries,
     libcerror_error_t **error )
{
	libregf_transaction_log_entry_t **entries = NULL;
	libregf_transaction_log_t **logs           = NULL;
	uint8_t **used_entries                     = NULL;
	static char *function                      = "libregf_transaction_log_select_hvle_entries";
	size_t entry_index                         = 0;
	size_t log_index                           = 0;
	size_t maximum_number_of_entries           = 0;
	size_t selected_entry_index                = 0;
	int found_entry                            = 0;
	int selected_log_index                     = -1;
	uint32_t expected_sequence_number          = 0;

	if( ( transaction_logs == NULL )
	 || ( hive_header == NULL )
	 || ( selected_entries == NULL )
	 || ( selected_logs == NULL )
	 || ( number_of_selected_entries == NULL ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid argument.",
		 function );

		return( -1 );
	}
	*selected_entries           = NULL;
	*selected_logs              = NULL;
	*number_of_selected_entries = 0;

	for( log_index = 0;
	     log_index < (size_t) number_of_transaction_logs;
	     log_index++ )
	{
		if( ( transaction_logs[ log_index ].format == LIBREGF_TRANSACTION_LOG_FORMAT_HVLE )
		 && ( transaction_logs[ log_index ].header.checksum_is_valid != 0 ) )
		{
			maximum_number_of_entries += transaction_logs[ log_index ].number_of_entries;
		}
	}
	if( maximum_number_of_entries == 0 )
	{
		return( 1 );
	}
	if( maximum_number_of_entries > ( MEMORY_MAXIMUM_ALLOCATION_SIZE / sizeof( libregf_transaction_log_entry_t * ) ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid maximum number of entries value exceeds maximum.",
		 function );

		return( -1 );
	}
	entries      = (libregf_transaction_log_entry_t **) memory_allocate(
	                                                    sizeof( libregf_transaction_log_entry_t * ) * maximum_number_of_entries );
	logs         = (libregf_transaction_log_t **) memory_allocate(
	                                               sizeof( libregf_transaction_log_t * ) * maximum_number_of_entries );
	used_entries = (uint8_t **) memory_allocate(
	                             sizeof( uint8_t * ) * number_of_transaction_logs );

	if( ( entries == NULL )
	 || ( logs == NULL )
	 || ( used_entries == NULL ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create selected entries.",
		 function );

		goto on_error;
	}
	memory_set(
	 used_entries,
	 0,
	 sizeof( uint8_t * ) * number_of_transaction_logs );

	for( log_index = 0;
	     log_index < (size_t) number_of_transaction_logs;
	     log_index++ )
	{
		if( transaction_logs[ log_index ].number_of_entries == 0 )
		{
			continue;
		}
		used_entries[ log_index ] = (uint8_t *) memory_allocate(
		                                          sizeof( uint8_t ) * transaction_logs[ log_index ].number_of_entries );

		if( used_entries[ log_index ] == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
			 "%s: unable to create used entries.",
			 function );

			goto on_error;
		}
		memory_set(
		 used_entries[ log_index ],
		 0,
		 sizeof( uint8_t ) * transaction_logs[ log_index ].number_of_entries );
	}
	if( hive_header->checksum_is_valid != 0 )
	{
		for( log_index = 0;
		     log_index < (size_t) number_of_transaction_logs;
		     log_index++ )
		{
			if( ( transaction_logs[ log_index ].format != LIBREGF_TRANSACTION_LOG_FORMAT_HVLE )
			 || ( transaction_logs[ log_index ].header.checksum_is_valid == 0 )
			 || ( transaction_logs[ log_index ].number_of_entries == 0 ) )
			{
				continue;
			}
			if( libregf_transaction_log_sequence_is_before(
			     transaction_logs[ log_index ].header.primary_sequence_number,
			     hive_header->secondary_sequence_number ) != 0 )
			{
				continue;
			}
			if( ( selected_log_index == -1 )
			 || ( libregf_transaction_log_sequence_is_before(
			       transaction_logs[ log_index ].header.primary_sequence_number,
			       transaction_logs[ selected_log_index ].header.primary_sequence_number ) != 0 ) )
			{
				selected_log_index = (int) log_index;
			}
		}
		if( selected_log_index == -1 )
		{
			goto on_success;
		}
		expected_sequence_number = transaction_logs[ selected_log_index ].header.primary_sequence_number;
	}
	else
	{
		for( log_index = 0;
		     log_index < (size_t) number_of_transaction_logs;
		     log_index++ )
		{
			if( ( transaction_logs[ log_index ].format != LIBREGF_TRANSACTION_LOG_FORMAT_HVLE )
			 || ( transaction_logs[ log_index ].header.checksum_is_valid == 0 )
			 || ( transaction_logs[ log_index ].number_of_entries == 0 ) )
			{
				continue;
			}
			if( ( selected_log_index == -1 )
			 || ( libregf_transaction_log_sequence_is_before(
			       transaction_logs[ selected_log_index ].header.primary_sequence_number,
			       transaction_logs[ log_index ].header.primary_sequence_number ) != 0 ) )
			{
				selected_log_index = (int) log_index;
			}
		}
		if( selected_log_index == -1 )
		{
			goto on_success;
		}
		expected_sequence_number = transaction_logs[ selected_log_index ].entries[ 0 ].sequence_number;
	}
	while( 1 )
	{
		found_entry = 0;

		for( log_index = 0;
		     log_index < (size_t) number_of_transaction_logs;
		     log_index++ )
		{
			if( ( transaction_logs[ log_index ].format != LIBREGF_TRANSACTION_LOG_FORMAT_HVLE )
			 || ( transaction_logs[ log_index ].header.checksum_is_valid == 0 ) )
			{
				continue;
			}
			for( entry_index = 0;
			     entry_index < transaction_logs[ log_index ].number_of_entries;
			     entry_index++ )
			{
				if( ( used_entries[ log_index ][ entry_index ] != 0 )
				 || ( transaction_logs[ log_index ].entries[ entry_index ].sequence_number != expected_sequence_number ) )
				{
					continue;
				}
				entries[ selected_entry_index ] = &( transaction_logs[ log_index ].entries[ entry_index ] );
				logs[ selected_entry_index ]    = &( transaction_logs[ log_index ] );

				used_entries[ log_index ][ entry_index ] = 1;
				selected_entry_index++;
				found_entry = 1;

				break;
			}
			if( found_entry != 0 )
			{
				break;
			}
		}
		if( found_entry == 0 )
		{
			break;
		}
		expected_sequence_number++;
	}
on_success:
	for( log_index = 0;
	     log_index < (size_t) number_of_transaction_logs;
	     log_index++ )
	{
		if( used_entries[ log_index ] != NULL )
		{
			memory_free(
			 used_entries[ log_index ] );
		}
	}
	memory_free(
	 used_entries );

	if( selected_entry_index == 0 )
	{
		memory_free(
		 entries );
		memory_free(
		 logs );

		return( 1 );
	}
	*selected_entries           = entries;
	*selected_logs              = logs;
	*number_of_selected_entries = selected_entry_index;

	return( 1 );

on_error:
	if( used_entries != NULL )
	{
		for( log_index = 0;
		     log_index < (size_t) number_of_transaction_logs;
		     log_index++ )
		{
			if( used_entries[ log_index ] != NULL )
			{
				memory_free(
				 used_entries[ log_index ] );
			}
		}
		memory_free(
		 used_entries );
	}
	if( entries != NULL )
	{
		memory_free(
		 entries );
	}
	if( logs != NULL )
	{
		memory_free(
		 logs );
	}
	return( -1 );
}

/* Applies HvLE transaction logs
 * Returns 1 if successful, 0 if no recovery was possible or -1 on error
 */
int libregf_transaction_log_apply_hvle(
     libregf_transaction_log_t *transaction_logs,
     int number_of_transaction_logs,
     const uint8_t *hive_data,
     size_t hive_data_size,
     const libregf_transaction_log_header_t *hive_header,
     uint8_t **recovered_data,
     size_t *recovered_data_size,
     uint32_t *last_sequence_number,
     int *number_of_recovered_pages,
     libcerror_error_t **error )
{
	libregf_transaction_log_entry_t **selected_entries = NULL;
	libregf_transaction_log_entry_t *entry             = NULL;
	libregf_transaction_log_t **selected_logs           = NULL;
	libregf_transaction_log_t *base_log                 = NULL;
	const uint8_t *page_data                            = NULL;
	static char *function                               = "libregf_transaction_log_apply_hvle";
	size_t dirty_page_data_offset                       = 0;
	size_t entry_index                                  = 0;
	size_t log_index                                    = 0;
	size_t maximum_recovered_data_size                  = 0;
	size_t number_of_selected_entries                   = 0;
	size_t page_index                                   = 0;
	size_t target_offset                                = 0;
	uint64_t dirty_pages_data_size                      = 0;
	uint32_t page_offset                                = 0;
	uint32_t page_size                                  = 0;
	int result                                          = 0;

	if( ( transaction_logs == NULL )
	 || ( hive_data == NULL )
	 || ( hive_header == NULL )
	 || ( recovered_data == NULL )
	 || ( recovered_data_size == NULL )
	 || ( last_sequence_number == NULL )
	 || ( number_of_recovered_pages == NULL ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid argument.",
		 function );

		return( -1 );
	}
	if( libregf_transaction_log_select_hvle_entries(
	     transaction_logs,
	     number_of_transaction_logs,
	     hive_header,
	     &selected_entries,
	     &selected_logs,
	     &number_of_selected_entries,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to select HvLE log entries.",
		 function );

		goto on_error;
	}
	if( number_of_selected_entries == 0 )
	{
		return( 0 );
	}
	maximum_recovered_data_size = hive_data_size;

	for( entry_index = 0;
	     entry_index < number_of_selected_entries;
	     entry_index++ )
	{
		entry = selected_entries[ entry_index ];

		if( ( entry->hive_bins_size < LIBREGF_TRANSACTION_LOG_HIVE_BIN_SIZE )
		 || ( ( entry->hive_bins_size % LIBREGF_TRANSACTION_LOG_HIVE_BIN_SIZE ) != 0 ) )
		{
			break;
		}
		if( (uint64_t) entry->hive_bins_size > ( (uint64_t) SSIZE_MAX - LIBREGF_TRANSACTION_LOG_HIVE_BIN_SIZE ) )
		{
			break;
		}
		dirty_pages_data_size = 0;

		for( page_index = 0;
		     page_index < entry->number_of_dirty_pages;
		     page_index++ )
		{
			byte_stream_copy_to_uint32_little_endian(
			 &( selected_logs[ entry_index ]->data[ entry->dirty_page_references_offset + ( page_index * 8 ) ] ),
			 page_offset );

			byte_stream_copy_to_uint32_little_endian(
			 &( selected_logs[ entry_index ]->data[ entry->dirty_page_references_offset + ( page_index * 8 ) + 4 ] ),
			 page_size );

			if( ( page_size == 0 )
			 || ( ( (uint64_t) page_offset + page_size ) > entry->hive_bins_size ) )
			{
				break;
			}
			dirty_pages_data_size += page_size;
		}
		if( page_index < entry->number_of_dirty_pages )
		{
			break;
		}
		if( dirty_pages_data_size > ( entry->size - LIBREGF_TRANSACTION_LOG_HVLE_HEADER_SIZE - ( (uint64_t) entry->number_of_dirty_pages * 8 ) ) )
		{
			break;
		}
		if( ( (size_t) entry->hive_bins_size + LIBREGF_TRANSACTION_LOG_HIVE_BIN_SIZE ) > maximum_recovered_data_size )
		{
			maximum_recovered_data_size = (size_t) entry->hive_bins_size + LIBREGF_TRANSACTION_LOG_HIVE_BIN_SIZE;
		}
	}
	if( entry_index == 0 )
	{
		result = 0;

		goto on_cleanup;
	}
	number_of_selected_entries = entry_index;

	if( libregf_transaction_log_resize_recovered_data(
	     recovered_data,
	     recovered_data_size,
	     maximum_recovered_data_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to resize recovered data.",
		 function );

		goto on_error;
	}
	if( hive_data_size <= *recovered_data_size )
	{
		memory_copy(
		 *recovered_data,
		 hive_data,
		 hive_data_size );
	}
	else
	{
		memory_copy(
		 *recovered_data,
		 hive_data,
		 *recovered_data_size );
	}
	if( hive_header->checksum_is_valid == 0 )
	{
		base_log = selected_logs[ number_of_selected_entries - 1 ];

		for( log_index = 0;
		     log_index < (size_t) number_of_transaction_logs;
		     log_index++ )
		{
			if( ( transaction_logs[ log_index ].format == LIBREGF_TRANSACTION_LOG_FORMAT_HVLE )
			 && ( transaction_logs[ log_index ].header.checksum_is_valid != 0 )
			 && ( libregf_transaction_log_sequence_is_before(
			       base_log->header.primary_sequence_number,
			       transaction_logs[ log_index ].header.primary_sequence_number ) != 0 ) )
			{
				base_log = &( transaction_logs[ log_index ] );
			}
		}
		memory_copy(
		 *recovered_data,
		 base_log->data,
		 LIBREGF_TRANSACTION_LOG_HEADER_SIZE );
	}
	for( entry_index = 0;
	     entry_index < number_of_selected_entries;
	     entry_index++ )
	{
		entry                  = selected_entries[ entry_index ];
		dirty_page_data_offset = entry->dirty_page_data_offset;

		for( page_index = 0;
		     page_index < entry->number_of_dirty_pages;
		     page_index++ )
		{
			byte_stream_copy_to_uint32_little_endian(
			 &( selected_logs[ entry_index ]->data[ entry->dirty_page_references_offset + ( page_index * 8 ) ] ),
			 page_offset );

			byte_stream_copy_to_uint32_little_endian(
			 &( selected_logs[ entry_index ]->data[ entry->dirty_page_references_offset + ( page_index * 8 ) + 4 ] ),
			 page_size );

			page_data     = &( selected_logs[ entry_index ]->data[ dirty_page_data_offset ] );
			target_offset = LIBREGF_TRANSACTION_LOG_HIVE_BIN_SIZE + page_offset;

			if( ( target_offset > *recovered_data_size )
			 || ( page_size > ( *recovered_data_size - target_offset ) ) )
			{
				break;
			}
			memory_copy(
			 &( ( *recovered_data )[ target_offset ] ),
			 page_data,
			 page_size );

			dirty_page_data_offset += page_size;
			(*number_of_recovered_pages)++;
		}
	}
	if( libregf_transaction_log_update_header(
	     *recovered_data,
	     *recovered_data_size,
	     selected_entries[ number_of_selected_entries - 1 ]->sequence_number,
	     selected_entries[ number_of_selected_entries - 1 ]->hive_bins_size,
	     1,
	     selected_entries[ number_of_selected_entries - 1 ]->flags,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_SET_FAILED,
		 "%s: unable to update recovered hive header.",
		 function );

		goto on_error;
	}
	*last_sequence_number = selected_entries[ number_of_selected_entries - 1 ]->sequence_number;
	result                = 1;

on_cleanup:
	memory_free(
	 selected_entries );
	memory_free(
	 selected_logs );

	return( result );

on_error:
	if( selected_entries != NULL )
	{
		memory_free(
		 selected_entries );
	}
	if( selected_logs != NULL )
	{
		memory_free(
		 selected_logs );
	}
	return( -1 );
}

/* Recovers a hive using transaction log data
 * Returns 1 if successful, 0 if no recovery was possible or -1 on error
 */
int libregf_transaction_log_recover_data(
     uint8_t **recovered_data,
     size_t *recovered_data_size,
     uint32_t *last_sequence_number,
     int *number_of_recovered_pages,
     const uint8_t *hive_data,
     size_t hive_data_size,
     const uint8_t *transaction_log1_data,
     size_t transaction_log1_data_size,
     const uint8_t *transaction_log2_data,
     size_t transaction_log2_data_size,
     libcerror_error_t **error )
{
	libregf_transaction_log_header_t hive_header;
	libregf_transaction_log_t transaction_logs[ 2 ];
	static char *function          = "libregf_transaction_log_recover_data";
	int number_of_transaction_logs = 0;
	int result                     = 0;

	if( ( recovered_data == NULL )
	 || ( recovered_data_size == NULL )
	 || ( last_sequence_number == NULL )
	 || ( number_of_recovered_pages == NULL )
	 || ( hive_data == NULL ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid argument.",
		 function );

		return( -1 );
	}
	*recovered_data            = NULL;
	*recovered_data_size       = 0;
	*last_sequence_number      = 0;
	*number_of_recovered_pages = 0;

	if( hive_data_size < LIBREGF_TRANSACTION_LOG_HEADER_SIZE )
	{
		return( 0 );
	}
	if( libregf_transaction_log_read_header(
	     &hive_header,
	     hive_data,
	     hive_data_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_READ_FAILED,
		 "%s: unable to read hive header.",
		 function );

		return( -1 );
	}
	if( ( hive_header.signature_is_valid == 0 )
	 || ( hive_header.file_type != LIBREGF_TRANSACTION_LOG_FILE_TYPE_PRIMARY ) )
	{
		return( 0 );
	}
	/* A clean hive is not modified by stale transaction logs.
	 */
	if( ( hive_header.checksum_is_valid != 0 )
	 && ( hive_header.primary_sequence_number == hive_header.secondary_sequence_number ) )
	{
		return( 0 );
	}
	memory_set(
	 transaction_logs,
	 0,
	 sizeof( libregf_transaction_log_t ) * 2 );

	if( ( transaction_log1_data != NULL )
	 && ( transaction_log1_data_size > 0 ) )
	{
		if( libregf_transaction_log_parse(
		     &( transaction_logs[ number_of_transaction_logs ] ),
		     transaction_log1_data,
		     transaction_log1_data_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_READ_FAILED,
			 "%s: unable to parse transaction log 1.",
			 function );

			goto on_error;
		}
		number_of_transaction_logs++;
	}
	if( ( transaction_log2_data != NULL )
	 && ( transaction_log2_data_size > 0 ) )
	{
		if( libregf_transaction_log_parse(
		     &( transaction_logs[ number_of_transaction_logs ] ),
		     transaction_log2_data,
		     transaction_log2_data_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_READ_FAILED,
			 "%s: unable to parse transaction log 2.",
			 function );

			goto on_error;
		}
		number_of_transaction_logs++;
	}
	result = libregf_transaction_log_apply_hvle(
	          transaction_logs,
	          number_of_transaction_logs,
	          hive_data,
	          hive_data_size,
	          &hive_header,
	          recovered_data,
	          recovered_data_size,
	          last_sequence_number,
	          number_of_recovered_pages,
	          error );

	if( result == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 "%s: unable to apply HvLE transaction logs.",
		 function );

		goto on_error;
	}
	if( result == 0 )
	{
		result = libregf_transaction_log_apply_dirt(
		          transaction_logs,
		          number_of_transaction_logs,
		          hive_data,
		          hive_data_size,
		          &hive_header,
		          recovered_data,
		          recovered_data_size,
		          last_sequence_number,
		          number_of_recovered_pages,
		          error );

		if( result == -1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_RUNTIME,
			 LIBCERROR_RUNTIME_ERROR_GENERIC,
			 "%s: unable to apply DIRT transaction logs.",
			 function );

			goto on_error;
		}
	}
	for( result = 0;
	     result < number_of_transaction_logs;
	     result++ )
	{
		libregf_transaction_log_free(
		 &( transaction_logs[ result ] ),
		 NULL );
	}
	if( *recovered_data == NULL )
	{
		return( 0 );
	}
	return( 1 );

on_error:
	for( result = 0;
	     result < number_of_transaction_logs;
	     result++ )
	{
		libregf_transaction_log_free(
		 &( transaction_logs[ result ] ),
		 NULL );
	}
	if( *recovered_data != NULL )
	{
		memory_free(
		 *recovered_data );

		*recovered_data      = NULL;
		*recovered_data_size = 0;
	}
	return( -1 );
}

/* Reads the contents of a file IO handle
 * Returns 1 if successful or -1 on error
 */
int libregf_transaction_log_read_file_io_handle(
     libbfio_handle_t *file_io_handle,
     uint8_t **data,
     size_t *data_size,
     libcerror_error_t **error )
{
	static char *function      = "libregf_transaction_log_read_file_io_handle";
	size64_t file_size         = 0;
	ssize_t read_count         = 0;
	int file_io_handle_is_open = 0;
	int result                 = 0;

	if( ( file_io_handle == NULL )
	 || ( data == NULL )
	 || ( data_size == NULL ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid argument.",
		 function );

		return( -1 );
	}
	*data      = NULL;
	*data_size = 0;

	file_io_handle_is_open = libbfio_handle_is_open(
	                          file_io_handle,
	                          error );

	if( file_io_handle_is_open == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_OPEN_FAILED,
		 "%s: unable to determine if file IO handle is open.",
		 function );

		return( -1 );
	}
	else if( file_io_handle_is_open == 0 )
	{
		if( libbfio_handle_open(
		     file_io_handle,
		     LIBBFIO_OPEN_READ,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_OPEN_FAILED,
			 "%s: unable to open file IO handle.",
			 function );

			return( -1 );
		}
	}
	if( libbfio_handle_get_size(
	     file_io_handle,
	     &file_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GET_FAILED,
		 "%s: unable to retrieve file size.",
		 function );

		goto on_error;
	}
	if( ( file_size == 0 )
	 || ( file_size > (size64_t) SSIZE_MAX ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid file size value exceeds maximum.",
		 function );

		goto on_error;
	}
	*data = (uint8_t *) memory_allocate(
	                    sizeof( uint8_t ) * (size_t) file_size );

	if( *data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create data.",
		 function );

		goto on_error;
	}
	read_count = libbfio_handle_read_buffer_at_offset(
	              file_io_handle,
	              *data,
	              (size_t) file_size,
	              0,
	              error );

	if( read_count != (ssize_t) file_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_READ_FAILED,
		 "%s: unable to read data.",
		 function );

		goto on_error;
	}
	if( file_io_handle_is_open == 0 )
	{
		result = libbfio_handle_close(
		          file_io_handle,
		          error );

		if( result != 0 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_CLOSE_FAILED,
			 "%s: unable to close file IO handle.",
			 function );

			goto on_error;
		}
	}
	*data_size = (size_t) file_size;

	return( 1 );

on_error:
	if( file_io_handle_is_open == 0 )
	{
		libbfio_handle_close(
		 file_io_handle,
		 NULL );
	}
	if( *data != NULL )
	{
		memory_free(
		 *data );

		*data = NULL;
	}
	return( -1 );
}

/* Recovers a hive using transaction log file IO handles
 * Returns 1 if successful, 0 if no recovery was possible or -1 on error
 */
int libregf_transaction_log_recover_file_io_handles(
     libbfio_handle_t *hive_file_io_handle,
     libbfio_handle_t *transaction_log1_file_io_handle,
     libbfio_handle_t *transaction_log2_file_io_handle,
     uint8_t **recovered_data,
     size_t *recovered_data_size,
     uint32_t *last_sequence_number,
     int *number_of_recovered_pages,
     libcerror_error_t **error )
{
	uint8_t file_header_data[ LIBREGF_TRANSACTION_LOG_HEADER_SIZE ];
	libregf_transaction_log_header_t hive_header;
	uint8_t *hive_data                = NULL;
	size_t hive_data_size             = 0;
	uint8_t *transaction_log1_data    = NULL;
	size_t transaction_log1_data_size = 0;
	uint8_t *transaction_log2_data    = NULL;
	size_t transaction_log2_data_size = 0;
	static char *function             = "libregf_transaction_log_recover_file_io_handles";
	ssize_t read_count                = 0;
	int file_io_handle_is_open        = 0;
	int result                        = 0;

	if( ( hive_file_io_handle == NULL )
	 || ( recovered_data == NULL )
	 || ( recovered_data_size == NULL )
	 || ( last_sequence_number == NULL )
	 || ( number_of_recovered_pages == NULL ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid argument.",
		 function );

		return( -1 );
	}
	*recovered_data            = NULL;
	*recovered_data_size       = 0;
	*last_sequence_number      = 0;
	*number_of_recovered_pages = 0;

	if( ( transaction_log1_file_io_handle == NULL )
	 && ( transaction_log2_file_io_handle == NULL ) )
	{
		return( 0 );
	}
	file_io_handle_is_open = libbfio_handle_is_open(
	                          hive_file_io_handle,
	                          error );

	if( file_io_handle_is_open == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_OPEN_FAILED,
		 "%s: unable to determine if file IO handle is open.",
		 function );

		return( -1 );
	}
	else if( file_io_handle_is_open == 0 )
	{
		if( libbfio_handle_open(
		     hive_file_io_handle,
		     LIBBFIO_OPEN_READ,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_OPEN_FAILED,
			 "%s: unable to open hive file IO handle.",
			 function );

			return( -1 );
		}
	}
	read_count = libbfio_handle_read_buffer_at_offset(
	              hive_file_io_handle,
	              file_header_data,
	              LIBREGF_TRANSACTION_LOG_HEADER_SIZE,
	              0,
	              error );

	if( file_io_handle_is_open == 0 )
	{
		if( libbfio_handle_close(
		     hive_file_io_handle,
		     error ) != 0 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_CLOSE_FAILED,
			 "%s: unable to close hive file IO handle.",
			 function );

			return( -1 );
		}
	}
	if( read_count != (ssize_t) LIBREGF_TRANSACTION_LOG_HEADER_SIZE )
	{
		return( 0 );
	}
	if( libregf_transaction_log_read_header(
	     &hive_header,
	     file_header_data,
	     LIBREGF_TRANSACTION_LOG_HEADER_SIZE,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_READ_FAILED,
		 "%s: unable to read hive header.",
		 function );

		return( -1 );
	}
	if( ( hive_header.signature_is_valid == 0 )
	 || ( hive_header.file_type != LIBREGF_TRANSACTION_LOG_FILE_TYPE_PRIMARY ) )
	{
		return( 0 );
	}
	if( ( hive_header.checksum_is_valid != 0 )
	 && ( hive_header.primary_sequence_number == hive_header.secondary_sequence_number ) )
	{
		return( 0 );
	}
	if( libregf_transaction_log_read_file_io_handle(
	     hive_file_io_handle,
	     &hive_data,
	     &hive_data_size,
	     error ) != 1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_IO,
		 LIBCERROR_IO_ERROR_READ_FAILED,
		 "%s: unable to read hive data.",
		 function );

		goto on_error;
	}
	if( transaction_log1_file_io_handle != NULL )
	{
		if( libregf_transaction_log_read_file_io_handle(
		     transaction_log1_file_io_handle,
		     &transaction_log1_data,
		     &transaction_log1_data_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_READ_FAILED,
			 "%s: unable to read transaction log 1 data.",
			 function );

			goto on_error;
		}
	}
	if( transaction_log2_file_io_handle != NULL )
	{
		if( libregf_transaction_log_read_file_io_handle(
		     transaction_log2_file_io_handle,
		     &transaction_log2_data,
		     &transaction_log2_data_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_IO,
			 LIBCERROR_IO_ERROR_READ_FAILED,
			 "%s: unable to read transaction log 2 data.",
			 function );

			goto on_error;
		}
	}
	result = libregf_transaction_log_recover_data(
	          recovered_data,
	          recovered_data_size,
	          last_sequence_number,
	          number_of_recovered_pages,
	          hive_data,
	          hive_data_size,
	          transaction_log1_data,
	          transaction_log1_data_size,
	          transaction_log2_data,
	          transaction_log2_data_size,
	          error );

	if( result == -1 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_GENERIC,
		 "%s: unable to recover hive data.",
		 function );

		goto on_error;
	}
	memory_free(
	 hive_data );

	if( transaction_log1_data != NULL )
	{
		memory_free(
		 transaction_log1_data );
	}
	if( transaction_log2_data != NULL )
	{
		memory_free(
		 transaction_log2_data );
	}
	return( result );

on_error:
	if( hive_data != NULL )
	{
		memory_free(
		 hive_data );
	}
	if( transaction_log1_data != NULL )
	{
		memory_free(
		 transaction_log1_data );
	}
	if( transaction_log2_data != NULL )
	{
		memory_free(
		 transaction_log2_data );
	}
	return( -1 );
}

