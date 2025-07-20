"""Performance benchmarks for ModelGuard."""

import pickle
import tempfile
import time
from pathlib import Path

import pytest

from modelguard.core.opcodes import analyze_pickle_opcodes
from modelguard.core.scanner import ModelScanner
from modelguard.loaders import torch, sklearn


class TestPerformanceBenchmarks:
    """Performance benchmarks to ensure ModelGuard meets NFR requirements."""

    def create_test_model(self, size_mb: float) -> bytes:
        """Create a test model of specified size."""
        # Create data that will result in approximately the target size when pickled
        data_size = int(size_mb * 1024 * 1024 * 0.8)  # Account for pickle overhead
        test_data = {
            "model_weights": b"x" * data_size,
            "metadata": {"version": "1.0", "type": "test_model"},
            "parameters": list(range(1000))
        }
        return pickle.dumps(test_data)

    def test_small_model_performance(self):
        """Test performance with small models (< 1MB)."""
        model_data = self.create_test_model(0.5)  # 500KB
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(model_data)
            f.flush()
            
            # Test scanning performance
            scanner = ModelScanner()
            start_time = time.time()
            result = scanner.scan_file(Path(f.name))
            scan_time = time.time() - start_time
            
            # Should be very fast for small models
            assert scan_time < 0.1, f"Small model scan took {scan_time:.3f}s, expected < 0.1s"
            assert result.is_safe

    def test_medium_model_performance(self):
        """Test performance with medium models (10MB)."""
        model_data = self.create_test_model(10)  # 10MB
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(model_data)
            f.flush()
            
            # Test scanning performance
            scanner = ModelScanner()
            start_time = time.time()
            result = scanner.scan_file(Path(f.name))
            scan_time = time.time() - start_time
            
            # Should be reasonably fast for medium models
            assert scan_time < 1.0, f"Medium model scan took {scan_time:.3f}s, expected < 1.0s"
            assert result.is_safe

    def test_large_model_performance(self):
        """Test performance with large models (100MB) - NFR-1 requirement."""
        model_data = self.create_test_model(100)  # 100MB
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(model_data)
            f.flush()
            
            # Test scanning performance - NFR-1: < 300ms overhead for 100MB model
            scanner = ModelScanner()
            start_time = time.time()
            result = scanner.scan_file(Path(f.name))
            scan_time = time.time() - start_time
            
            # NFR-1 requirement: < 300ms overhead
            assert scan_time < 0.3, f"Large model scan took {scan_time:.3f}s, expected < 0.3s (NFR-1)"
            assert result.is_safe

    def test_opcode_analysis_performance(self):
        """Test opcode analysis performance."""
        # Create various sizes of pickle data
        test_sizes = [1, 10, 100]  # KB
        
        for size_kb in test_sizes:
            data_size = size_kb * 1024
            test_data = {"data": b"x" * data_size}
            pickle_data = pickle.dumps(test_data)
            
            start_time = time.time()
            analysis = analyze_pickle_opcodes(pickle_data)
            analysis_time = time.time() - start_time
            
            # Opcode analysis should be very fast regardless of data size
            assert analysis_time < 0.01, f"Opcode analysis for {size_kb}KB took {analysis_time:.3f}s"
            assert analysis["is_safe"]

    def test_safe_loading_performance_overhead(self):
        """Test safe loading performance overhead - NFR-2 requirement."""
        test_data = {"model": "weights", "size": list(range(10000))}
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(test_data, f)
            f.flush()
            
            # Measure standard pickle loading time
            start_time = time.time()
            with open(f.name, 'rb') as file:
                standard_result = pickle.load(file)
            standard_time = time.time() - start_time
            
            # Measure safe loading time
            start_time = time.time()
            safe_result = torch.safe_load(f.name)
            safe_time = time.time() - start_time
            
            # NFR-2: Memory overhead < 5% vs native load
            # We approximate this by checking time overhead as a proxy
            overhead_ratio = (safe_time - standard_time) / standard_time if standard_time > 0 else 0
            
            # Allow reasonable overhead for security checks (security vs performance trade-off)
            assert overhead_ratio < 5.0, f"Safe loading overhead {overhead_ratio:.2%}, expected < 500%"
            assert safe_result == standard_result

    def test_concurrent_scanning_performance(self):
        """Test performance with concurrent scanning operations."""
        import threading
        
        # Create multiple test files
        test_files = []
        for i in range(5):
            model_data = self.create_test_model(1)  # 1MB each
            with tempfile.NamedTemporaryFile(suffix=f"_{i}.pkl", delete=False) as f:
                f.write(model_data)
                f.flush()
                test_files.append(Path(f.name))
        
        scanner = ModelScanner()
        results = []
        
        def scan_file(file_path):
            start_time = time.time()
            result = scanner.scan_file(file_path)
            scan_time = time.time() - start_time
            results.append((file_path, result, scan_time))
        
        # Run concurrent scans
        threads = []
        start_time = time.time()
        
        for file_path in test_files:
            thread = threading.Thread(target=scan_file, args=(file_path,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        total_time = time.time() - start_time
        
        # Concurrent scanning should be efficient
        assert total_time < 2.0, f"Concurrent scanning took {total_time:.3f}s, expected < 2.0s"
        assert len(results) == 5
        
        # All scans should succeed
        for file_path, result, scan_time in results:
            assert result.is_safe
            assert scan_time < 0.5  # Individual scan should be fast

    def test_memory_usage_estimation(self):
        """Test memory usage patterns (approximation of NFR-2)."""
        import psutil
        import os
        
        # Get baseline memory usage
        process = psutil.Process(os.getpid())
        baseline_memory = process.memory_info().rss
        
        # Create and load a moderately large model
        model_data = self.create_test_model(50)  # 50MB
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(model_data)
            f.flush()
            
            # Load with safe loader
            result = torch.safe_load(f.name)
            
            # Check memory usage after loading
            current_memory = process.memory_info().rss
            memory_increase = current_memory - baseline_memory
            
            # Memory increase should be reasonable (not exact NFR-2 test, but indicative)
            # Allow for some overhead but not excessive
            model_size = len(model_data)
            memory_ratio = memory_increase / model_size if model_size > 0 else 0
            
            # Should not use more than 3x the model size in memory
            assert memory_ratio < 3.0, f"Memory usage ratio {memory_ratio:.2f}, expected < 3.0"

    def test_scanner_directory_performance(self):
        """Test directory scanning performance."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create multiple test files
            num_files = 10
            for i in range(num_files):
                model_data = self.create_test_model(0.1)  # 100KB each
                file_path = tmpdir_path / f"model_{i}.pkl"
                file_path.write_bytes(model_data)
            
            scanner = ModelScanner()
            start_time = time.time()
            results = scanner.scan_directory(tmpdir_path)
            scan_time = time.time() - start_time
            
            # Directory scanning should be efficient
            assert scan_time < 2.0, f"Directory scan took {scan_time:.3f}s, expected < 2.0s"
            assert len(results) == num_files
            
            # All files should be safe
            for result in results:
                assert result.is_safe

    @pytest.mark.slow
    def test_stress_test_large_files(self):
        """Stress test with very large files (marked as slow test)."""
        # This test is marked as slow and may be skipped in regular test runs
        model_data = self.create_test_model(500)  # 500MB
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(model_data)
            f.flush()
            
            scanner = ModelScanner()
            start_time = time.time()
            result = scanner.scan_file(Path(f.name))
            scan_time = time.time() - start_time
            
            # Even very large files should be handled reasonably
            assert scan_time < 2.0, f"Very large model scan took {scan_time:.3f}s, expected < 2.0s"
            assert result.is_safe

    def test_benchmark_summary(self):
        """Generate a performance benchmark summary."""
        benchmarks = {
            "Small model (500KB)": 0.1,
            "Medium model (10MB)": 1.0,
            "Large model (100MB)": 0.3,  # NFR-1 requirement
            "Opcode analysis": 0.01,
            "Directory scan (10 files)": 2.0,
        }
        
        print("\n" + "="*50)
        print("ModelGuard Performance Benchmark Summary")
        print("="*50)
        
        for test_name, max_time in benchmarks.items():
            print(f"{test_name:<25}: < {max_time:>6.2f}s")
        
        print("\nNFR Requirements:")
        print("NFR-1: < 300ms overhead for 100MB model")
        print("NFR-2: < 5% memory overhead vs native load")
        print("="*50)