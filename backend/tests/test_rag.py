import pytest
from unittest.mock import patch, MagicMock
from rag.cwe_fetcher import CWEFetcher
from rag.chroma_service import ChromaService
from agents.discovery import run_discovery_agent, fallback_heuristic_analyzer

class TestRAGModule:
    
    @patch('rag.cwe_fetcher.requests.get')
    def test_cwe_fetcher_success(self, mock_get):
        # Mock successful HTML response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = """
        <html>
            <h2>CWE-89: Improper Neutralization of Special Elements</h2>
            <div id="Description"><div class="detail">SQL Injection description.</div></div>
            <div id="Potential_Mitigations"><div class="detail">Use parameterized queries.</div></div>
        </html>
        """
        mock_get.return_value = mock_response
        
        result = CWEFetcher.fetch_cwe_details("CWE-89")
        assert result is not None
        assert result["cwe_id"] == "CWE-89"
        assert "Improper Neutralization" in result["title"]
        assert "SQL Injection description." in result["context"]
        assert "Use parameterized queries." in result["context"]

    @patch('rag.cwe_fetcher.requests.get')
    def test_cwe_fetcher_failure(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        result = CWEFetcher.fetch_cwe_details("CWE-9999")
        assert result is None

    @patch('rag.chroma_service.os.getenv')
    def test_chroma_service_fallback(self, mock_getenv):
        # Test when no API key is provided
        mock_getenv.return_value = None
        
        service = ChromaService()
        assert not service.use_gemini
        
        # Test index and query with default local embeddings
        with patch.object(CWEFetcher, 'fetch_cwe_details', return_value={
            "cwe_id": "CWE-TEST", 
            "title": "Test Title", 
            "context": "Test Context"
        }):
            success = service.index_cwe("CWE-TEST")
            assert success
            
            results = service.query_cwe("Test", n_results=1)
            assert len(results) > 0
            assert results[0]["cwe_id"] == "CWE-TEST"

    def test_discovery_fallback_heuristic(self):
        diff_text = "query = f'SELECT * FROM users WHERE username={username}'"
        result = fallback_heuristic_analyzer(diff_text)
        
        assert len(result) == 1
        assert result[0]["cwe_id"] == "CWE-89"
        assert result[0]["vulnerability_name"] == "SQL Injection"

    @patch('agents.discovery.genai.GenerativeModel')
    @patch('agents.discovery.os.getenv')
    def test_discovery_agent_success(self, mock_getenv, mock_model):
        mock_getenv.return_value = "fake_key"
        
        mock_instance = MagicMock()
        mock_response = MagicMock()
        # Ensure it returns valid JSON string
        mock_response.text = '[{"cwe_id": "CWE-79", "vulnerability_name": "XSS", "file_path": "index.html", "line_start": 1, "line_end": 2, "suspect_code": "<script>", "reasoning": "test"}]'
        mock_instance.generate_content.return_value = mock_response
        mock_model.return_value = mock_instance
        
        result = run_discovery_agent("<div>{user_input}</div>")
        assert len(result) == 1
        assert result[0]["cwe_id"] == "CWE-79"
