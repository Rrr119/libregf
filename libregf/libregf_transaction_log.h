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

#if !defined( _LIBREGF_TRANSACTION_LOG_H )
#define _LIBREGF_TRANSACTION_LOG_H

#include <common.h>
#include <types.h>

#include "libregf_libbfio.h"
#include "libregf_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

int libregf_transaction_log_calculate_marvin32(
     uint64_t *hash_value,
     const uint8_t *data,
     size_t data_size,
     libcerror_error_t **error );

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
     libcerror_error_t **error );

int libregf_transaction_log_recover_file_io_handles(
     libbfio_handle_t *hive_file_io_handle,
     libbfio_handle_t *transaction_log1_file_io_handle,
     libbfio_handle_t *transaction_log2_file_io_handle,
     uint8_t **recovered_data,
     size_t *recovered_data_size,
     uint32_t *last_sequence_number,
     int *number_of_recovered_pages,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBREGF_TRANSACTION_LOG_H ) */
