/* contrib/data_encryption/data_encryption--1.1.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION data_encryption" to load this file. \quit

--
-- cipher_definition.sql
--

/*------------------------------------------------------------*
 * cipher_key_definition
 * 
 * define type, function, index end etc for TDE.
 *------------------------------------------------------------*/

SET search_path TO public;
SET check_function_bodies TO off;


/* define a new procedural language */
/* CREATE TRUSTED LANGUAGE 'plpgsql' HANDLER language_handler_in;*/

	/* drop if encrypted data types are already exist */
	--DROP TYPE IF EXISTS encrypt_text CASCADE;
	--DROP TYPE IF EXISTS encrypt_bytea CASCADE;

	/* create encrypted data types */
	CREATE TYPE encrypt_text;
	CREATE TYPE encrypt_bytea;

	/* define input function of encrypted text type */
	CREATE FUNCTION
		enctext_in(cstring)
	RETURNS
		encrypt_text
	AS
		'$libdir/data_encryption.so','enctext_in'
	LANGUAGE C STABLE STRICT;

	/* define output function of encrypted text type */
	CREATE FUNCTION
		enctext_out(encrypt_text)
	RETURNS
		cstring
	AS
		'$libdir/data_encryption.so','enctext_out'
	LANGUAGE C STABLE STRICT;

	/* define recv function of encrypted text type */
	CREATE FUNCTION 
		enctext_recv(internal)
	RETURNS
		encrypt_text
	AS
		'$libdir/data_encryption.so','encrecv'
	LANGUAGE C IMMUTABLE STRICT;

	/* define send function of encrypted text type */
	CREATE FUNCTION 
		enctext_send(encrypt_text)
	RETURNS
		bytea
	AS
		'$libdir/data_encryption.so','encsend'
	LANGUAGE C IMMUTABLE STRICT;

	/* define input function of encrypted binary type */
	CREATE FUNCTION
		encbytea_in(cstring)
	RETURNS
		encrypt_bytea
	AS
		'$libdir/data_encryption.so','encbytea_in'
	LANGUAGE C STABLE STRICT;

	/* define output function of encrypted binary type */
	CREATE FUNCTION
		encbytea_out(encrypt_bytea)
	RETURNS
		cstring
	AS
		'$libdir/data_encryption.so','encbytea_out'
	LANGUAGE C STABLE STRICT;
	
	/* define recv function of encrypted binary type */
	CREATE FUNCTION 
		encbytea_recv(internal)
	RETURNS
		encrypt_bytea
	AS
		'$libdir/data_encryption.so','encrecv'
	LANGUAGE C IMMUTABLE STRICT;

	/* define send function of encrypted binary type */
	CREATE FUNCTION 
		encbytea_send(encrypt_bytea)
	RETURNS
		bytea
	AS
		'$libdir/data_encryption.so','encsend'
	LANGUAGE C IMMUTABLE STRICT;

	/* define encrypted text types */
	CREATE TYPE ENCRYPT_TEXT (
		INPUT = enctext_in
		, OUTPUT = enctext_out
		, RECEIVE = enctext_recv
		, SEND = enctext_send
		, INTERNALLENGTH = VARIABLE
		, ALIGNMENT = int4
		, STORAGE = extended
		, CATEGORY = 'S');

	/* define encrypted binary types */
	CREATE TYPE ENCRYPT_BYTEA (
		INPUT = encbytea_in
		, OUTPUT = encbytea_out
		, RECEIVE = encbytea_recv
		, SEND = encbytea_send
		, INTERNALLENGTH = VARIABLE
		, ALIGNMENT = int4
		, STORAGE = extended
		, CATEGORY = 'U');

	/* index operator of encrypted text types */
	CREATE OR REPLACE FUNCTION
		enc_compeq_enctext(encrypt_text,encrypt_text)
	RETURNS
		bool
	AS
		'$libdir/data_encryption.so','enc_compeq_enctext'
	LANGUAGE C STABLE STRICT;

	/* index operator of encrypted binary types */
	CREATE OR REPLACE FUNCTION
		enc_compeq_encbytea(encrypt_bytea,encrypt_bytea)
	RETURNS
		bool
	AS
		'$libdir/data_encryption.so','enc_compeq_encbytea'
	LANGUAGE C STABLE STRICT;

	/* hash function for encrypted text */
	CREATE OR REPLACE FUNCTION
		enc_hash_enctext(encrypt_text)
	RETURNS
		integer
	AS
		'$libdir/data_encryption.so','enc_hash_encdata'
	LANGUAGE C STRICT IMMUTABLE;

	/* hash function for encrypted binary */
	CREATE OR REPLACE FUNCTION
		enc_hash_encbytea(encrypt_bytea)
	RETURNS
		integer
	AS
		'$libdir/data_encryption.so','enc_hash_encdata'
	LANGUAGE C STRICT IMMUTABLE;

	/* load current encryption key */
	CREATE OR REPLACE FUNCTION
		enc_store_key_info(text, text)
	RETURNS
		bool
	AS
		'$libdir/data_encryption.so','enc_store_key_info'
	LANGUAGE C STRICT;
	
	/* load old key to memory for re-encryption */
	CREATE OR REPLACE FUNCTION
		enc_store_old_key_info(text, text)
	RETURNS
		bool
	AS
		'$libdir/data_encryption.so','enc_store_old_key_info'
	LANGUAGE C STRICT;

	/* drops key information from memory */
	CREATE OR REPLACE FUNCTION
		enc_drop_key_info()
	RETURNS
		bool
	AS
		'$libdir/data_encryption.so','enc_drop_key_info'
	LANGUAGE C STRICT;

	/* drops old key information from memory  */
	CREATE OR REPLACE FUNCTION
		enc_drop_old_key_info()
	RETURNS
		bool
	AS
		'$libdir/data_encryption.so','enc_drop_old_key_info'
	LANGUAGE C STRICT;

	/* rename bakcup file, if it is exists */
	CREATE OR REPLACE FUNCTION
		enc_rename_backupfile(text,text)
	RETURNS
		bool
	AS
		'$libdir/data_encryption.so','enc_rename_backupfile'
	LANGUAGE C STRICT;

	/* backup current parameters of loglevel */
	CREATE OR REPLACE FUNCTION
		enc_save_logsetting()
	RETURNS
		bool
	AS
		'$libdir/data_encryption.so','enc_save_logsetting'
	LANGUAGE C STRICT;

	/* restore log parameters from backup */
	CREATE OR REPLACE FUNCTION
		enc_restore_logsetting()
	RETURNS
		bool
	AS
		'$libdir/data_encryption.so','enc_restore_logsetting'
	LANGUAGE C STRICT;

/* define index operator */
	/* for encrypted text */
	CREATE OPERATOR = (
	leftarg = encrypt_text, rightarg = encrypt_text, procedure = enc_compeq_enctext, restrict = eqsel, join = eqjoinsel );
	/* for encrypted binary */
	CREATE OPERATOR = (
	leftarg = encrypt_bytea, rightarg = encrypt_bytea, procedure = enc_compeq_encbytea, restrict = eqsel, join = eqjoinsel );

/* define index for encrypted type column */
	/* define hash index for encrypted text */
	CREATE OPERATOR CLASS
		hashtext_enc_ops
	DEFAULT FOR TYPE
		encrypt_text
	USING
		hash
	AS
		OPERATOR		1	   = (encrypt_text,encrypt_text),
		FUNCTION		1	   enc_hash_enctext(encrypt_text);

	/* define hash index for encrypted binary */
	CREATE OPERATOR CLASS
		hashbytea_enc_ops
	DEFAULT FOR TYPE
		encrypt_bytea
	USING
		hash
	AS
		OPERATOR 		1	   = (encrypt_bytea,encrypt_bytea),
		FUNCTION 		1	   enc_hash_encbytea(encrypt_bytea);

/* define cast function for encrypted type column */
	CREATE OR REPLACE FUNCTION
		enctext(boolean)
	RETURNS
		encrypt_text
	AS
		'$libdir/data_encryption.so','boolenctext'
	LANGUAGE C STRICT;

	CREATE OR REPLACE FUNCTION
		enctext(character)
	RETURNS
		encrypt_text
	AS
		'$libdir/data_encryption.so','enctextrtrim'
	LANGUAGE C STABLE STRICT;

	CREATE OR REPLACE FUNCTION
		enctext(inet)
	RETURNS
		encrypt_text
	AS
		'$libdir/data_encryption.so','inetenctext'
	LANGUAGE C STABLE STRICT;

	CREATE OR REPLACE FUNCTION
		enctext(xml)
	RETURNS
		encrypt_text
	AS
		'$libdir/data_encryption.so','xmlenctext'
	LANGUAGE C STABLE STRICT;

	CREATE OR REPLACE FUNCTION
		regclass(encrypt_text)
	RETURNS
		regclass
	AS
		'$libdir/data_encryption.so','enctext_regclass'
	LANGUAGE C STABLE STRICT;

	/* encrypted test -> text */
	CREATE CAST
		(encrypt_text AS text)
	WITH INOUT
	AS IMPLICIT;
	/* text -> encrypted text */
	CREATE CAST
		(text AS encrypt_text)
	WITH INOUT
	AS ASSIGNMENT;
	/* boolean -> encrypted text */
	CREATE CAST
		(boolean AS encrypt_text)
	WITH FUNCTION enctext(boolean)
	AS ASSIGNMENT;
	/* character -> encrypted text */
	CREATE CAST
		(character AS encrypt_text)
	WITH FUNCTION enctext(character)
	AS ASSIGNMENT;
	/* cidr -> encrypted text */
	CREATE CAST
		(cidr AS encrypt_text)
	WITH FUNCTION enctext(inet)
	AS ASSIGNMENT;
	/* inet -> encrypted text */
	CREATE CAST
		(inet AS encrypt_text)
	WITH FUNCTION enctext(inet)
	AS ASSIGNMENT;
	/* xml -> encrypted text */
	CREATE CAST
		(xml AS encrypt_text)
	WITH FUNCTION enctext(xml)
	AS ASSIGNMENT;
	/* encrypted text -> regclass */
	CREATE CAST
		(encrypt_text AS regclass)
	WITH FUNCTION regclass(encrypt_text)
	AS ASSIGNMENT;

	/* binary -> encrypted binary */
	CREATE CAST
		(encrypt_bytea AS bytea)
	WITH INOUT
	AS IMPLICIT;
	/* encrypted binary -> binary */
	CREATE CAST
		(bytea AS encrypt_bytea)
	WITH INOUT
	AS ASSIGNMENT;

/* define table for managing encryption key */
--	DROP TABLE IF EXISTS cipher_key_table;
	CREATE TABLE cipher_key_table (key BYTEA
								, algorithm TEXT);

--
-- cipher_key_function.sql
--
SET search_path TO public;
SET check_function_bodies TO off;

/*------------------------------------------------------------*
 * Function : cipher_key_regist
 *
 * add new key to the encryption key table
 * 
 * @param TEXT $1	current encryption key
 * @param TEXT $2	new encryption key
 * @param TEXT $3	encryption algorithm
 *------------------------------------------------------------*/
CREATE OR REPLACE FUNCTION cipher_key_regist (TEXT, TEXT, TEXT) RETURNS INTEGER AS $$

DECLARE
	current_cipher_key  ALIAS FOR $1;
	cipher_key  ALIAS FOR $2;
	cipher_algorithm ALIAS FOR $3;

	current_cipher_algorithm TEXT;
	
	f_key_num SMALLINT;			/* number of encryption key*/

BEGIN
	/* if flag of checking log_statement is 'on', checking parameters */		
	IF (SELECT setting FROM pg_settings WHERE name = 'encrypt.checklogparam') = 'on' THEN
		/* of  log_statement is 'all' stop process and loggin error */
		IF (SELECT setting FROM pg_settings WHERE name = 'log_statement') = 'all' THEN
			RAISE EXCEPTION 'TDE-E0001 log_statement must not be ''all''(02)';
		END IF;
	END IF;

	IF cipher_key IS NULL OR cipher_key = '' THEN
		RAISE EXCEPTION 'TDE-E0002 new cipher key is invalid(01)';
	END IF;

	/* validate encryption algorithm */
	IF cipher_algorithm != 'aes' AND cipher_algorithm != 'bf' THEN
		RAISE EXCEPTION 'TDE-E0003 invalid cipher algorithm "%"(01)', cipher_algorithm;
	END IF;

	SET LOCAL search_path TO public;
	SET LOCAL enable_seqscan TO off;

	/* obtain lock of enryption key table */
	LOCK TABLE cipher_key_table IN EXCLUSIVE MODE;

	/* getting the number of encryption key */
	SELECT count(*) INTO f_key_num FROM cipher_key_table;
	/* if encryption key is already exist */
	IF f_key_num = 1 THEN
		IF current_cipher_key IS NULL THEN
			RAISE EXCEPTION 'TDE-E0008 current cipher key is not correct(01)';
		END IF;
		/* if current key is valid and save current encryption algorithm*/
		BEGIN
			SELECT algorithm INTO current_cipher_algorithm FROM cipher_key_table WHERE pgp_sym_decrypt(key, current_cipher_key)=current_cipher_key;
		EXCEPTION
			WHEN SQLSTATE '39000' THEN
				RAISE EXCEPTION 'TDE-E0008 current cipher key is not correct(01)';
		END;
		/* delete current key */
		DELETE FROM cipher_key_table;

	/* too many key is exists */
	ELSEIF f_key_num > 1 THEN
			RAISE EXCEPTION 'TDE-E0009 too many encryption keys are exists in cipher_key_table(01)';
	END IF;
	
	/* encrypt and register new key */
	INSERT INTO cipher_key_table VALUES(pgp_sym_encrypt(cipher_key, cipher_key, 'cipher-algo=aes256, s2k-mode=1'), cipher_algorithm);
	
	/* backup encryption key table */
	PERFORM cipher_key_backup();
	/* reencrypt all data */
	IF f_key_num = 1 THEN
		PERFORM cipher_key_reencrypt_data(current_cipher_key, current_cipher_algorithm, cipher_key);
	END IF;

	/* return 1 */
	RETURN 1;
END;
$$ LANGUAGE plpgsql;


/*------------------------------------------------------------*
 * Function : cipher_key_reencrypt_data
 * 
 * re-encrypt specified data periodically using encryption key 
 * which is specified custom parameter
 * 
 * @return true if re-encryption is successfully done
 *------------------------------------------------------------*/
CREATE OR REPLACE FUNCTION cipher_key_reencrypt_data (TEXT, TEXT, TEXT) RETURNS BOOLEAN AS $$

DECLARE

	old_cipher_key ALIAS FOR $1;
	old_cipher_algorithm ALIAS FOR $2;
	new_cipher_key  ALIAS FOR $3;

	f_rec RECORD;	/* store target update column */
	f_rec2 RECORD;	/* store target update row */
	f_cu	REFCURSOR;	/* fetch target update column */
	f_cu2	REFCURSOR;	/* fetch target update row */

	f_counter	BIGINT;		/* number of processed target record*/
	f_result	BIGINT;

	f_query TEXT;					/* store dynamic SQL string */
	
	f_relid BIGINT;
	f_nspname TEXT;
	f_relname TEXT;
	f_islast BOOLEAN;

BEGIN
	/* init */
	f_counter := 0;
	f_relid := 0;
	f_nspname = '';
	f_relname = '';
	f_islast = FALSE;

	SET LOCAL search_path TO public;
	SET LOCAL encrypt.enable TO on;
	SET LOCAL encrypt.noversionerror TO on;
	
	/* set new key to memory */
	PERFORM pgtde_begin_session(new_cipher_key);
	/* set old key to memory */
	PERFORM enc_store_old_key_info(old_cipher_key, old_cipher_algorithm);

	/* store column of user defined table */
	OPEN
		f_cu
	FOR
		SELECT a.attrelid, n.nspname, c.relname, a.attname, t.typname
		FROM pg_attribute a, pg_class c, pg_type t, pg_namespace n
		WHERE a.attrelid = c.oid
		AND t.oid = a.atttypid
		AND c.relnamespace = n.oid
		AND c.relkind = 'r'
		AND t.typname IN ('encrypt_text', 'encrypt_bytea')
		AND n.nspname != 'information_schema'
		AND n.nspname NOT LIKE E'pg\\_%'
		ORDER BY nspname, relname, attname;
	

	/* re-encryption */
	FETCH f_cu INTO f_rec;
	IF NOT FOUND THEN
		f_islast := TRUE;
	END IF;

	/* update each encrypted column */
	LOOP
		IF f_islast THEN
			EXIT;
		END IF;

		f_relid := f_rec.attrelid;
		f_nspname := f_rec.nspname;
		f_relname := f_rec.relname;

		f_query := 'UPDATE ONLY ' || quote_ident(f_rec.nspname) || '.' || quote_ident(f_rec.relname) || ' SET ';

		LOOP
			IF f_rec.typname = 'encrypt_text' THEN
				f_query := f_query || quote_ident(f_rec.attname) || ' = ' || quote_ident(f_rec.attname) || '::text::encrypt_text ';
			ELSE
				f_query := f_query || quote_ident(f_rec.attname) || ' = ' || quote_ident(f_rec.attname) || '::bytea::encrypt_bytea ';
			END IF;

			FETCH f_cu INTO f_rec;
			IF NOT FOUND THEN
				f_islast := TRUE;
			END IF;

			IF f_islast OR f_relid != f_rec.attrelid THEN
				f_query := f_query || ';';
				EXIT;
			ELSE
				f_query := f_query || ', ';
			END IF;
		END LOOP;

		RAISE INFO 'TDE-I0001 re-encryption of table "%"."%" was started(01)', f_nspname, f_relname;

		EXECUTE f_query;

		RAISE INFO 'TDE-I0002 re-encryption of table "%"."%" was completed(01)', f_nspname, f_relname;
	END LOOP;

	CLOSE f_cu;
	
	/* delete old key from memory */
	PERFORM enc_drop_old_key_info();
	/* drop key from memory */
	PERFORM pgtde_end_session();

	RETURN TRUE;
END;
$$ LANGUAGE plpgsql;


/*------------------------------------------------------------*
 * Function : cipher_key_backup
 *
 * backup encryption key table
 * if backup already exists, rename backup to <filename>.sv
 * and backup current key table
 * 
 * @return true, if 
 *------------------------------------------------------------*/
CREATE OR REPLACE FUNCTION cipher_key_backup () RETURNS BOOLEAN AS $$

DECLARE
	f_filepath TEXT;	/* path of backupfile */
	f_old_filepath TEXT;	/* old backupfile */
	f_query TEXT;		/* dynamic SQL */
	f_dbname TEXT;		/* current dbname */
	result BOOLEAN;

BEGIN
	/* get path of backup file from encrypt.backup */
	SELECT setting INTO f_filepath FROM pg_settings WHERE name = 'encrypt.backup';

	/* if encrypt.backup is not set, get value of data_directory */
	IF(f_filepath = '')THEN
		SELECT setting INTO f_filepath FROM pg_settings WHERE name = 'data_directory';

		IF f_filepath IS NULL THEN
			RAISE EXCEPTION 'TDE-E0014 could not get data directory path(01)';
		END IF;
	END IF;

	/* get name of current db */
	SELECT current_database() INTO f_dbname;

	/* set filename of backup */
	f_filepath := f_filepath || E'/ck_backup_' || f_dbname;
	f_old_filepath := f_filepath || E'.sv';

	/* rename if "ck_backup" is already exists */
	SELECT enc_rename_backupfile(f_filepath, f_old_filepath) INTO result;

	IF result = FALSE THEN
		RAISE EXCEPTION 'TDE-E0015 could not rename old backup file of cipher key(01)';
	END IF;

	/* backup current encryption key table */
	f_query := 'COPY cipher_key_table TO ''' || f_filepath || '''';
	EXECUTE f_query;

	RETURN result;
END;
$$ LANGUAGE plpgsql
SET search_path TO public;


/*------------------------------------------------------------*
 * Function : cipher_key_disable_log
 * 
 * backup current log parameters and set log parameter 
 * to lower level
 * related parameter is log_statement, log_min_error_statement
 * and log_min_duration_statement
 * 
 * @return false if backup of log parameter is already exists
 *------------------------------------------------------------*/
CREATE OR REPLACE FUNCTION cipher_key_disable_log () RETURNS BOOLEAN AS $$

DECLARE
	save_result BOOLEAN;	/* result of backup current parameter */

BEGIN
	/* backup current parameters */
	SELECT enc_save_logsetting() INTO save_result;

	RETURN save_result;

END;
$$ LANGUAGE plpgsql
SET search_path TO public;


/*------------------------------------------------------------*
 * Function : cipher_key_enable_log
 *
 * restore log parameter from backup
 * related parameter is log_statement, log_min_error_statement
 * and log_min_duration_statement
 * 
 * @return false if backup is not exists
 *------------------------------------------------------------*/
CREATE OR REPLACE FUNCTION cipher_key_enable_log () RETURNS BOOLEAN AS $$

DECLARE
	save_result BOOLEAN;

BEGIN
	/* restore log parameter from backup */
	SELECT enc_restore_logsetting() INTO save_result;

	RETURN save_result;

END;
$$ LANGUAGE plpgsql
SET search_path TO public;

--
-- common_session_create.sql
--
SET search_path TO public;
SET check_function_bodies TO off;

/*------------------------------------------------------------*
 * Function : pgtde_begin_session
 * 
 * load encryption key table to memory
 * exception will be raised in below cases
 * 1. value of log_statement is 'all'
 * 2. encryption key is invalid 
 * 
 * @param TEXT $1	lastest encryption key
 * @return result of load encryption key table to memory
 *------------------------------------------------------------*/
CREATE OR REPLACE FUNCTION pgtde_begin_session (TEXT) RETURNS BOOLEAN AS $$

DECLARE
	cipher_key ALIAS FOR $1;

	f_algorithm TEXT;		/* encryption algorithm of lastest key */
	f_key_num INTEGER;		/* number of encryption key */
	f_result BOOLEAN;

BEGIN

	/* checking log_statement parameter if log encrypt.checklogparam is on */
	IF cipher_key IS NOT NULL AND (SELECT setting FROM pg_settings WHERE name = 'encrypt.checklogparam') = 'on' THEN
		/* function failed if log_statement is 'all' */
		IF (SELECT setting FROM pg_settings WHERE name = 'log_statement') = 'all' THEN
			RAISE EXCEPTION 'TDE-E0001 log_statement must not be ''all''(01)';
		END IF;
	END IF;

	/* drop encryption key information in memory */
	PERFORM enc_drop_key_info();
	/* drop old-encryption key information in memory */
	PERFORM enc_drop_old_key_info();

	IF cipher_key IS NOT NULL THEN
		/* get number of registered encryption key */
		SELECT count(*) INTO f_key_num FROM cipher_key_table;

		/* return false, if there is no or too many encryption key */
		IF f_key_num = 0 THEN
			RETURN FALSE;
		ELSIF f_key_num>1 THEN
			RAISE EXCEPTION 'TDE-E0009 too many encryption keys are exists in cipher_key_table(02)';
		END IF;

		BEGIN
			/* load encrption key table to memory */
			PERFORM enc_store_key_info(pgp_sym_decrypt(key, cipher_key), algorithm)
			FROM (SELECT key, algorithm FROM cipher_key_table) AS ckt;
		EXCEPTION
			WHEN SQLSTATE '39000' THEN
				PERFORM enc_drop_key_info();
				RAISE EXCEPTION 'TDE-E0012 cipher key is not correct(01)';
		END;
	END IF;
	RETURN TRUE;
END;
$$ LANGUAGE plpgsql
SET search_path TO public;


/*------------------------------------------------------------*
 * Function : pgtde_end_session
 * 
 * drop encryption key table from memory
 * return false, if there is no encryption key table in memory
 * 
 * @return result of drop encryption key table in memory
 *------------------------------------------------------------*/
CREATE OR REPLACE FUNCTION pgtde_end_session () RETURNS BOOLEAN AS $$

BEGIN
	/* drop encryption key table in memory */
	IF (SELECT enc_drop_key_info()) THEN
		RETURN TRUE;
	ELSE
		RETURN FALSE;
	END IF;
END;
$$ LANGUAGE plpgsql
SET search_path TO public;
