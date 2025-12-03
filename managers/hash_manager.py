import tlsh
import ssdeep
import logging

logger = logging.getLogger(__name__)


class HashManager:
    """Maneja el cálculo de TLSH/ssdeep y comparación con base de datos"""
    
    def __init__(self, database, similarity_index):
        """
        Args:
            database (dict): BD completa con formato {sha256: {metadata, hashes, ...}}
            similarity_index (dict): Índice de similitud {tlsh: {hash: sha256}, ssdeep: {...}}
        """
        self.database = database
        self.similarity_index = similarity_index
        logger.debug(f"HashManager initialized with {len(database)} entries")
    
    def calculate_tlsh(self, content):
        """
        Calcula TLSH sobre contenido procesado
        
        Args:
            content (bytes): Contenido del archivo procesado
            
        Returns:
            tuple: (success: bool, tlsh_hash: str | error_message: str)
        """
        content_size = len(content)
        
        # Validar tamaño mínimo
        if content_size < 50:
            logger.warning(f"Content too small for TLSH: {content_size} bytes")
            return False, f'Content too small for TLSH (min 50 bytes, got {content_size})'
        
        try:
            tlsh_hash = tlsh.hash(content)
            if tlsh_hash is None or tlsh_hash == "":
                logger.error("TLSH returned empty hash")
                return False, "TLSH returned empty hash (insufficient randomness)"
            
            logger.debug(f"TLSH calculated: {tlsh_hash[:16]}...")
            return True, tlsh_hash
            
        except Exception as e:
            logger.error(f"Error computing TLSH: {e}")
            return False, f'Cannot compute TLSH: {str(e)}'
    
    def calculate_ssdeep(self, content):
        """
        Calcula ssdeep sobre contenido procesado
        
        Args:
            content (bytes): Contenido del archivo procesado
            
        Returns:
            tuple: (success: bool, ssdeep_hash: str | error_message: str)
        """
        content_size = len(content)
        
        # ssdeep funciona mejor con archivos >= 4096 bytes
        if content_size < 4096:
            logger.warning(f"Content too small for ssdeep: {content_size} bytes")
            return False, f'Content too small for ssdeep (recommended min 4096 bytes, got {content_size})'
        
        try:
            ssdeep_hash = ssdeep.hash(content)
            if ssdeep_hash is None or ssdeep_hash == "":
                logger.error("ssdeep returned empty hash")
                return False, "ssdeep returned empty hash"
            
            logger.debug(f"ssdeep calculated: {ssdeep_hash[:32]}...")
            return True, ssdeep_hash
            
        except Exception as e:
            logger.error(f"Error computing ssdeep: {e}")
            return False, f'Cannot compute ssdeep: {str(e)}'
    
    def find_matches_tlsh(self, uploaded_hash, top_n=10):
        """
        Encuentra los matches más cercanos usando TLSH
        
        Args:
            uploaded_hash (str): Hash TLSH del archivo subido
            top_n (int): Número de top matches a retornar
            
        Returns:
            dict: Resultados de matching TLSH
        """
        best_match_sha256 = None
        best_match = None
        min_distance = float('inf')
        all_matches = []
        
        # Iterar sobre todos los hashes TLSH en el índice
        tlsh_index = self.similarity_index.get('tlsh', {})
        logger.debug(f"Comparing TLSH against {len(tlsh_index)} entries")
        
        for db_tlsh, sha256 in tlsh_index.items():
            try:
                distance = tlsh.diff(uploaded_hash, db_tlsh)
                
                # Obtener metadata completa del archivo
                file_entry = self.database.get(sha256, {})
                
                match_info = {
                    'sha256': sha256,
                    'name': file_entry.get('name', ['Unknown']),
                    'family': file_entry.get('family', 'Unknown'),
                    'file_type': file_entry.get('file_type', 'Unknown'),
                    'tags': file_entry.get('tags', []),
                    'tlsh': db_tlsh,
                    'distance': distance
                }
                
                all_matches.append(match_info)
                
                if distance < min_distance:
                    min_distance = distance
                    best_match_sha256 = sha256
                    best_match = file_entry
                    
            except Exception as e:
                logger.error(f"Error comparing TLSH with {sha256}: {e}")
                continue
        
        # Ordenar por distancia (menor = más similar)
        all_matches.sort(key=lambda x: x['distance'])
        top_matches = all_matches[:top_n]
        
        if best_match_sha256:
            logger.info(f"TLSH best match: {best_match_sha256} (distance: {min_distance})")
        else:
            logger.info("No TLSH matches found")
        
        return {
            'best_match': best_match,
            'best_match_sha256': best_match_sha256,
            'min_distance': min_distance if min_distance != float('inf') else None,
            'top_matches': top_matches,
            'all_matches_count': len(all_matches)
        }
    
    def find_matches_ssdeep(self, uploaded_hash, top_n=10):
        """
        Encuentra los matches más cercanos usando ssdeep
        
        Args:
            uploaded_hash (str): Hash ssdeep del archivo subido
            top_n (int): Número de top matches a retornar
            
        Returns:
            dict: Resultados de matching ssdeep
        """
        best_match_sha256 = None
        best_match = None
        max_similarity = 0
        all_matches = []
        
        # Iterar sobre todos los hashes ssdeep en el índice
        ssdeep_index = self.similarity_index.get('ssdeep', {})
        logger.debug(f"Comparing ssdeep against {len(ssdeep_index)} entries")
        
        for db_ssdeep, sha256 in ssdeep_index.items():
            try:
                # ssdeep.compare() retorna un valor 0-100 (100 = idéntico)
                similarity = ssdeep.compare(uploaded_hash, db_ssdeep)
                
                # Solo considerar si hay alguna similitud
                if similarity == 0:
                    continue
                
                # Obtener metadata completa del archivo
                file_entry = self.database.get(sha256, {})
                
                match_info = {
                    'sha256': sha256,
                    'name': file_entry.get('name', ['Unknown']),
                    'family': file_entry.get('family', 'Unknown'),
                    'file_type': file_entry.get('file_type', 'Unknown'),
                    'tags': file_entry.get('tags', []),
                    'ssdeep': db_ssdeep,
                    'similarity': similarity
                }
                
                all_matches.append(match_info)
                
                if similarity > max_similarity:
                    max_similarity = similarity
                    best_match_sha256 = sha256
                    best_match = file_entry
                    
            except Exception as e:
                logger.error(f"Error comparing ssdeep with {sha256}: {e}")
                continue
        
        # Ordenar por similitud (mayor = más similar)
        all_matches.sort(key=lambda x: x['similarity'], reverse=True)
        top_matches = all_matches[:top_n]
        
        if best_match_sha256:
            logger.info(f"ssdeep best match: {best_match_sha256} (similarity: {max_similarity}%)")
        else:
            logger.info("No ssdeep matches found")
        
        return {
            'best_match': best_match,
            'best_match_sha256': best_match_sha256,
            'max_similarity': max_similarity if max_similarity > 0 else None,
            'top_matches': top_matches,
            'all_matches_count': len(all_matches)
        }
    
    def compare_file(self, content, top_n=10, use_ssdeep=True):
        """
        Pipeline completo: calcula TLSH/ssdeep y encuentra matches
        
        Args:
            content (bytes): Contenido del archivo procesado
            top_n (int): Número de top matches a retornar
            use_ssdeep (bool): Si calcular también ssdeep
            
        Returns:
            tuple: (success: bool, result: dict | error_message: str)
        """
        logger.info(f"Starting hash comparison (content size: {len(content)} bytes, top_n: {top_n})")
        
        result = {
            'content_size': len(content),
            'tlsh': {},
            'ssdeep': {}
        }
        
        # Calcular TLSH
        success_tlsh, tlsh_result = self.calculate_tlsh(content)
        
        if not success_tlsh:
            logger.error(f"TLSH calculation failed: {tlsh_result}")
            return False, tlsh_result  # Error en TLSH
        
        uploaded_tlsh = tlsh_result
        result['tlsh']['hash'] = uploaded_tlsh
        
        # Buscar matches TLSH
        tlsh_matches = self.find_matches_tlsh(uploaded_tlsh, top_n)
        result['tlsh']['matches'] = tlsh_matches
        
        # Calcular ssdeep (opcional)
        if use_ssdeep:
            success_ssdeep, ssdeep_result = self.calculate_ssdeep(content)
            
            if success_ssdeep:
                uploaded_ssdeep = ssdeep_result
                result['ssdeep']['hash'] = uploaded_ssdeep
                
                # Buscar matches ssdeep
                ssdeep_matches = self.find_matches_ssdeep(uploaded_ssdeep, top_n)
                result['ssdeep']['matches'] = ssdeep_matches
            else:
                logger.warning(f"ssdeep calculation failed: {ssdeep_result}")
                result['ssdeep']['error'] = ssdeep_result
        
        logger.info("Hash comparison completed successfully")
        return True, result
