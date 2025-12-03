"""
Hash Manager Module

This module handles the calculation and comparison of similarity hashes
(TLSH and ssdeep) for file similarity detection.

Classes:
    HashManager: Main class for hash computation and database comparison

Dependencies:
    - tlsh: Trend Micro Locality Sensitive Hash library
    - ssdeep: Context-triggered piecewise hashing library
"""

import tlsh
import ssdeep
import logging

logger = logging.getLogger(__name__)


class HashManager:
    """
    Manages TLSH/ssdeep hash calculation and database comparison.

    This class provides methods to calculate similarity hashes for files
    and find similar files in a database by comparing hash values.

    Attributes:
        database (dict): Complete file database {sha256: {metadata}}
        similarity_index (dict): Fast lookup index {tlsh: {hash: sha256}, ssdeep: {hash: sha256}}
    """

    def __init__(self, database, similarity_index):
        """
        Initialize the HashManager.

        Args:
            database (dict): Complete database with format {sha256: {metadata, hashes, ...}}
            similarity_index (dict): Similarity index {tlsh: {hash: sha256}, ssdeep: {...}}
        """
        self.database = database
        self.similarity_index = similarity_index
        logger.debug(f"HashManager initialized with {len(database)} entries")

    def calculate_tlsh(self, content):
        """
        Calculate TLSH hash on processed content.

        TLSH (Trend Micro Locality Sensitive Hash) is designed to detect
        similar files even when they have been modified. It requires a
        minimum of 50 bytes to generate a valid hash.

        Args:
            content (bytes): Processed file content

        Returns:
            tuple: (success: bool, tlsh_hash: str | error_message: str)
                - If successful: (True, "T1ABC123...")
                - If failed: (False, "Error message")

        Raises:
            No exceptions raised - errors are returned in the tuple

        Example:
            >>> manager = HashManager(db, index)
            >>> success, hash_value = manager.calculate_tlsh(file_content)
            >>> if success:
            ...     print(f"TLSH: {hash_value}")
        """
        content_size = len(content)

        # Validate minimum size
        if content_size < 50:
            logger.warning(f"Content too small for TLSH: {content_size} bytes")
            return (
                False,
                f"Content too small for TLSH (min 50 bytes, got {content_size})",
            )

        try:
            tlsh_hash = tlsh.hash(content)
            if tlsh_hash is None or tlsh_hash == "":
                logger.error("TLSH returned empty hash")
                return False, "TLSH returned empty hash (insufficient randomness)"

            logger.debug(f"TLSH calculated: {tlsh_hash[:16]}...")
            return True, tlsh_hash

        except Exception as e:
            logger.error(f"Error computing TLSH: {e}")
            return False, f"Cannot compute TLSH: {str(e)}"

    def calculate_ssdeep(self, content):
        """
        Calculate ssdeep hash on processed content.

        ssdeep (Context Triggered Piecewise Hashing) is a fuzzy hashing
        algorithm that can match similar files. It works best with files
        of at least 4096 bytes.

        Args:
            content (bytes): Processed file content

        Returns:
            tuple: (success: bool, ssdeep_hash: str | error_message: str)
                - If successful: (True, "192:ABC...")
                - If failed: (False, "Error message")

        Example:
            >>> manager = HashManager(db, index)
            >>> success, hash_value = manager.calculate_ssdeep(file_content)
            >>> if success:
            ...     print(f"ssdeep: {hash_value}")
        """
        content_size = len(content)

        # ssdeep works better with files >= 4096 bytes
        if content_size < 4096:
            logger.warning(f"Content too small for ssdeep: {content_size} bytes")
            return (
                False,
                f"Content too small for ssdeep (recommended min 4096 bytes, got {content_size})",
            )

        try:
            ssdeep_hash = ssdeep.hash(content)
            if ssdeep_hash is None or ssdeep_hash == "":
                logger.error("ssdeep returned empty hash")
                return False, "ssdeep returned empty hash"

            logger.debug(f"ssdeep calculated: {ssdeep_hash[:32]}...")
            return True, ssdeep_hash

        except Exception as e:
            logger.error(f"Error computing ssdeep: {e}")
            return False, f"Cannot compute ssdeep: {str(e)}"

    def find_matches_tlsh(self, uploaded_hash, top_n=10):
        """
        Find the closest matches using TLSH distance.

        Compares the uploaded file's TLSH hash against all TLSH hashes
        in the database and returns the most similar files. Lower distance
        means more similar files.

        Args:
            uploaded_hash (str): TLSH hash of the uploaded file
            top_n (int): Number of top matches to return (default: 10)

        Returns:
            dict: TLSH matching results containing:
                - best_match (dict): Metadata of the best matching file
                - best_match_sha256 (str): SHA256 of best match
                - min_distance (int): Distance to best match (0 = identical)
                - top_matches (list): Top N matches sorted by distance
                - all_matches_count (int): Total number of matches found

        Example:
            >>> manager = HashManager(db, index)
            >>> results = manager.find_matches_tlsh("T1ABC...", top_n=5)
            >>> print(f"Best match distance: {results['min_distance']}")
            >>> for match in results['top_matches']:
            ...     print(f"{match['name']}: distance={match['distance']}")
        """
        best_match_sha256 = None
        best_match = None
        min_distance = float("inf")
        all_matches = []

        # Iterate over all TLSH hashes in the index
        tlsh_index = self.similarity_index.get("tlsh", {})
        logger.debug(f"Comparing TLSH against {len(tlsh_index)} entries")

        for db_tlsh, sha256 in tlsh_index.items():
            try:
                # Calculate distance (0 = identical, larger = more different)
                distance = tlsh.diff(uploaded_hash, db_tlsh)

                # Get complete file metadata
                file_entry = self.database.get(sha256, {})

                match_info = {
                    "sha256": sha256,
                    "name": file_entry.get("name", ["Unknown"]),
                    "family": file_entry.get("family", "Unknown"),
                    "file_type": file_entry.get("file_type", "Unknown"),
                    "tags": file_entry.get("tags", []),
                    "tlsh": db_tlsh,
                    "distance": distance,
                }

                all_matches.append(match_info)

                if distance < min_distance:
                    min_distance = distance
                    best_match_sha256 = sha256
                    best_match = file_entry

            except Exception as e:
                logger.error(f"Error comparing TLSH with {sha256}: {e}")
                continue

        # Sort by distance (lower = more similar)
        all_matches.sort(key=lambda x: x["distance"])
        top_matches = all_matches[:top_n]

        if best_match_sha256:
            logger.info(
                f"TLSH best match: {best_match_sha256} (distance: {min_distance})"
            )
        else:
            logger.info("No TLSH matches found")

        return {
            "best_match": best_match,
            "best_match_sha256": best_match_sha256,
            "min_distance": min_distance if min_distance != float("inf") else None,
            "top_matches": top_matches,
            "all_matches_count": len(all_matches),
        }

    def find_matches_ssdeep(self, uploaded_hash, top_n=10):
        """
        Find the closest matches using ssdeep similarity.

        Compares the uploaded file's ssdeep hash against all ssdeep hashes
        in the database and returns the most similar files. Higher similarity
        means more similar files (0-100 scale).

        Args:
            uploaded_hash (str): ssdeep hash of the uploaded file
            top_n (int): Number of top matches to return (default: 10)

        Returns:
            dict: ssdeep matching results containing:
                - best_match (dict): Metadata of the best matching file
                - best_match_sha256 (str): SHA256 of best match
                - max_similarity (int): Similarity to best match (0-100, 100 = identical)
                - top_matches (list): Top N matches sorted by similarity
                - all_matches_count (int): Total number of matches found

        Example:
            >>> manager = HashManager(db, index)
            >>> results = manager.find_matches_ssdeep("192:ABC...", top_n=5)
            >>> print(f"Best match similarity: {results['max_similarity']}%")
            >>> for match in results['top_matches']:
            ...     print(f"{match['name']}: {match['similarity']}%")
        """
        best_match_sha256 = None
        best_match = None
        max_similarity = 0
        all_matches = []

        # Iterate over all ssdeep hashes in the index
        ssdeep_index = self.similarity_index.get("ssdeep", {})
        logger.debug(f"Comparing ssdeep against {len(ssdeep_index)} entries")

        for db_ssdeep, sha256 in ssdeep_index.items():
            try:
                # ssdeep.compare() returns a value 0-100 (100 = identical)
                similarity = ssdeep.compare(uploaded_hash, db_ssdeep)

                # Only consider if there's any similarity
                if similarity == 0:
                    continue

                # Get complete file metadata
                file_entry = self.database.get(sha256, {})

                match_info = {
                    "sha256": sha256,
                    "name": file_entry.get("name", ["Unknown"]),
                    "family": file_entry.get("family", "Unknown"),
                    "file_type": file_entry.get("file_type", "Unknown"),
                    "tags": file_entry.get("tags", []),
                    "ssdeep": db_ssdeep,
                    "similarity": similarity,
                }

                all_matches.append(match_info)

                if similarity > max_similarity:
                    max_similarity = similarity
                    best_match_sha256 = sha256
                    best_match = file_entry

            except Exception as e:
                logger.error(f"Error comparing ssdeep with {sha256}: {e}")
                continue

        # Sort by similarity (higher = more similar)
        all_matches.sort(key=lambda x: x["similarity"], reverse=True)
        top_matches = all_matches[:top_n]

        if best_match_sha256:
            logger.info(
                f"ssdeep best match: {best_match_sha256} (similarity: {max_similarity}%)"
            )
        else:
            logger.info("No ssdeep matches found")

        return {
            "best_match": best_match,
            "best_match_sha256": best_match_sha256,
            "max_similarity": max_similarity if max_similarity > 0 else None,
            "top_matches": top_matches,
            "all_matches_count": len(all_matches),
        }

    def compare_file(self, content, top_n=10, use_ssdeep=True):
        """
        Complete pipeline: calculate TLSH/ssdeep and find matches.

        This is the main method that orchestrates the entire hash comparison
        process. It calculates both TLSH and ssdeep hashes (if requested)
        and finds similar files in the database.

        Args:
            content (bytes): Processed file content
            top_n (int): Number of top matches to return (default: 10)
            use_ssdeep (bool): Whether to also calculate ssdeep (default: True)

        Returns:
            tuple: (success: bool, result: dict | error_message: str)
                - If successful: (True, {content_size, tlsh, ssdeep})
                - If failed: (False, "Error message")

        Result Dictionary Structure:
            {
                'content_size': int,
                'tlsh': {
                    'hash': str,
                    'matches': {
                        'best_match': dict,
                        'best_match_sha256': str,
                        'min_distance': int,
                        'top_matches': list,
                        'all_matches_count': int
                    }
                },
                'ssdeep': {
                    'hash': str,
                    'matches': { ... } or 'error': str
                }
            }

        Example:
            >>> manager = HashManager(db, index)
            >>> success, result = manager.compare_file(file_content, top_n=5)
            >>> if success:
            ...     print(f"TLSH hash: {result['tlsh']['hash']}")
            ...     print(f"Best match: {result['tlsh']['matches']['best_match']}")
        """
        logger.info(
            f"Starting hash comparison (content size: {len(content)} bytes, top_n: {top_n})"
        )

        result = {"content_size": len(content), "tlsh": {}, "ssdeep": {}}

        # Calculate TLSH
        success_tlsh, tlsh_result = self.calculate_tlsh(content)

        if not success_tlsh:
            logger.error(f"TLSH calculation failed: {tlsh_result}")
            return False, tlsh_result  # Error in TLSH

        uploaded_tlsh = tlsh_result
        result["tlsh"]["hash"] = uploaded_tlsh

        # Find TLSH matches
        tlsh_matches = self.find_matches_tlsh(uploaded_tlsh, top_n)
        result["tlsh"]["matches"] = tlsh_matches

        # Calculate ssdeep (optional)
        if use_ssdeep:
            success_ssdeep, ssdeep_result = self.calculate_ssdeep(content)

            if success_ssdeep:
                uploaded_ssdeep = ssdeep_result
                result["ssdeep"]["hash"] = uploaded_ssdeep

                # Find ssdeep matches
                ssdeep_matches = self.find_matches_ssdeep(uploaded_ssdeep, top_n)
                result["ssdeep"]["matches"] = ssdeep_matches
            else:
                logger.warning(f"ssdeep calculation failed: {ssdeep_result}")
                result["ssdeep"]["error"] = ssdeep_result

        logger.info("Hash comparison completed successfully")
        return True, result
