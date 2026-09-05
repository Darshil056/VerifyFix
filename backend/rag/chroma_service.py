import os
import logging
import chromadb
from chromadb.config import Settings
import google.generativeai as genai
from typing import List, Dict, Optional
from rag.cwe_fetcher import CWEFetcher

logger = logging.getLogger(__name__)

class ChromaService:
    """
    Manages the ChromaDB vector store and Gemini embeddings for Threat Intelligence.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ChromaService, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        # Configure Gemini API
        self.api_key = os.getenv("GEMINI_API_KEY")
        if self.api_key:
            genai.configure(api_key=self.api_key)
            self.use_gemini = True
        else:
            self.use_gemini = False
            logger.warning("No GEMINI_API_KEY found. ChromaDB will fall back to default local sentence-transformers.")

        # Initialize ChromaDB persistent client
        db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "chroma_data")
        os.makedirs(db_path, exist_ok=True)
        
        self.client = chromadb.PersistentClient(path=db_path, settings=Settings(allow_reset=True))
        self.collection_name = "threat_intelligence"
        
        # Get or create collection
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"}
        )
        logger.info(f"ChromaService initialized. Collection: {self.collection_name}. Gemini Embeddings: {self.use_gemini}")

    def _get_embedding(self, text: str) -> List[float]:
        """Generate embedding using Gemini API if available, else return None (let Chroma use default)"""
        if not self.use_gemini:
            return None # Chroma will use its default embedding function
            
        try:
            result = genai.embed_content(
                model="models/embedding-001",
                content=text,
                task_type="retrieval_document",
            )
            return result['embedding']
        except Exception as e:
            logger.error(f"Gemini embedding failed: {e}. Falling back to default.")
            return None

    def index_cwe(self, cwe_id: str) -> bool:
        """
        Fetch CWE details online and index them into ChromaDB.
        Returns True if successful, False otherwise.
        """
        # Check if it already exists
        existing = self.collection.get(ids=[cwe_id])
        if existing and existing['ids']:
            logger.info(f"{cwe_id} already indexed in ChromaDB.")
            return True

        # Fetch from MITRE
        cwe_data = CWEFetcher.fetch_cwe_details(cwe_id)
        if not cwe_data:
            logger.warning(f"Could not index {cwe_id}: Fetch failed or no data.")
            return False

        # Generate embedding
        context = cwe_data["context"]
        embedding = self._get_embedding(context)
        
        # Add to ChromaDB
        try:
            if embedding:
                self.collection.add(
                    documents=[context],
                    metadatas=[{"cwe_id": cwe_id, "title": cwe_data["title"]}],
                    ids=[cwe_id],
                    embeddings=[embedding]
                )
            else:
                # Use default embedding function
                self.collection.add(
                    documents=[context],
                    metadatas=[{"cwe_id": cwe_id, "title": cwe_data["title"]}],
                    ids=[cwe_id]
                )
            logger.info(f"Successfully indexed {cwe_id} into ChromaDB.")
            return True
        except Exception as e:
            logger.error(f"Failed to insert {cwe_id} into ChromaDB: {e}")
            return False

    def query_cwe(self, query_text: str, n_results: int = 3) -> List[Dict]:
        """
        Search the vector database for relevant threat intelligence context.
        """
        try:
            embedding = self._get_embedding(query_text)
            
            if embedding:
                results = self.collection.query(
                    query_embeddings=[embedding],
                    n_results=n_results
                )
            else:
                results = self.collection.query(
                    query_texts=[query_text],
                    n_results=n_results
                )
                
            if not results['documents'] or not results['documents'][0]:
                return []
                
            # Format results
            formatted_results = []
            for i in range(len(results['ids'][0])):
                formatted_results.append({
                    "cwe_id": results['ids'][0][i],
                    "title": results['metadatas'][0][i].get("title", ""),
                    "context": results['documents'][0][i],
                    "distance": results['distances'][0][i] if 'distances' in results and results['distances'] else 0.0
                })
                
            return formatted_results
            
        except Exception as e:
            logger.error(f"Error querying ChromaDB: {e}")
            return []
