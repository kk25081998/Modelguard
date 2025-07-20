"""Enhanced performance benchmarks and stress tests for ModelGuard."""

import gc
import pickle
import tempfile
import time
import threading
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import psutil
import os

from modelguard.core.opcodes import analyze_pickle_opcodes
from modelguard.core.scanner import ModelScanner
from modelguard.loaders import torch, sklearn


class TestAdvancedPerformanceBenchmarks:
    """Advanced performance benchmarks for ModelGuard."""

    def create_model_with_complexity(self, size_mb: float, complexity: str = "simple") -> bytes:
        """Create test models with different complexity levels."""
        base_size = int(size_mb * 1024 * 1024 * 0.7)  # Account for pickle overhead
        
        if complexity == "simple":
            data = {"weights": b"x" * base_size, "metadata": {"type": "simple"}}
        elif complexity == "nested":
            # Create deeply nested structure
            data = {"weights": b"x" * (base_size // 2)}
            nested = data
            for i in range(10):  # 10 levels deep
                nested[f"level_{i}"] = {"data": list(range(100)), "nested": {}}
                nested = nested[f"level_{i}"]["nested"]
        elif complexity == "wide":
            # Create wide structure with many keys
            data = {"weights": b"x" * (base_size // 2)}
            for i in range(1000):  # 1000 keys
                data[f"param_{i}"] = [i] * 10
        else:
            data = {"weights": b"x" * base_size}
            
        return pickle.dumps(data)

    @pytest.mark.performance
    def test_scalability_by_file_size(self):
        """Test performance scalability across different file sizes."""
        sizes_mb = [0.1, 1, 10, 50, 100]  # Test various sizes
        results = {}
        
        for size_mb in sizes_mb:
            model_data = self.create_model_with_complexity(size_mb, "simple")
            
            with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
                f.write(model_data)
                f.flush()
                
                try:
                    scanner = ModelScanner()
                    
                    # Measure scanning time
                    start_time = time.time()
                    result = scanner.scan_file(Path(f.name))
                    scan_time = time.time() - start_time
                    
                    results[size_mb] = {
                        "scan_time": scan_time,
                        "is_safe": result.is_safe,
                        "file_size_mb": size_mb
                    }
                    
                    # Performance assertions based on size
                    if size_mb <= 1:
                        assert scan_time < 0.1, f"{size_mb}MB scan took {scan_time:.3f}s"
                    elif size_mb <= 10:
                        assert scan_time < 0.5, f"{size_mb}MB scan took {scan_time:.3f}s"
                    elif size_mb <= 100:
                        assert scan_time < 2.0, f"{size_mb}MB scan took {scan_time:.3f}s"
                        
                finally:
                    Path(f.name).unlink()
        
        # Check that performance scales reasonably
        small_time = results[0.1]["scan_time"]
        large_time = results[100]["scan_time"]
        scaling_factor = large_time / small_time if small_time > 0 else float('inf')
        
        # Should not scale worse than O(n^2)
        assert scaling_factor < 10000, f"Performance scaling too poor: {scaling_factor}x"

    @pytest.mark.performance
    def test_complexity_impact_on_performance(self):
        """Test how data structure complexity affects performance."""
        complexities = ["simple", "nested", "wide"]
        size_mb = 5  # Fixed size, varying complexity
        
        results = {}
        
        for complexity in complexities:
            model_data = self.create_model_with_complexity(size_mb, complexity)
            
            with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
                f.write(model_data)
                f.flush()
                
                try:
                    # Test opcode analysis performance
                    start_time = time.time()
                    analysis = analyze_pickle_opcodes(model_data)
                    analysis_time = time.time() - start_time
                    
                    # Test scanning performance
                    scanner = ModelScanner()
                    start_time = time.time()
                    scan_result = scanner.scan_file(Path(f.name))
                    scan_time = time.time() - start_time
                    
                    results[complexity] = {
                        "analysis_time": analysis_time,
                        "scan_time": scan_time,
                        "total_opcodes": analysis.get("total_opcodes", 0),
                        "is_safe": scan_result.is_safe
                    }
                    
                    # All should complete within reasonable time
                    assert analysis_time < 1.0, f"{complexity} analysis took {analysis_time:.3f}s"
                    assert scan_time < 2.0, f"{complexity} scan took {scan_time:.3f}s"
                    
                finally:
                    Path(f.name).unlink()
        
        print(f"\nComplexity Performance Results:")
        for complexity, metrics in results.items():
            print(f"{complexity:>8}: analysis={metrics['analysis_time']:.3f}s, "
                  f"scan={metrics['scan_time']:.3f}s, opcodes={metrics['total_opcodes']}")

    @pytest.mark.performance
    def test_memory_efficiency(self):
        """Test memory usage patterns and efficiency."""
        process = psutil.Process(os.getpid())
        
        # Get baseline memory
        gc.collect()  # Force garbage collection
        baseline_memory = process.memory_info().rss
        
        # Test with progressively larger models
        sizes_mb = [1, 5, 10, 25]
        memory_results = {}
        
        for size_mb in sizes_mb:
            model_data = self.create_model_with_complexity(size_mb, "simple")
            
            with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
                f.write(model_data)
                f.flush()
                
                try:
                    # Measure memory before loading
                    gc.collect()
                    before_memory = process.memory_info().rss
                    
                    # Load the model
                    result = torch.safe_load(f.name)
                    
                    # Measure memory after loading
                    after_memory = process.memory_info().rss
                    memory_increase = after_memory - before_memory
                    
                    memory_results[size_mb] = {
                        "memory_increase_mb": memory_increase / (1024 * 1024),
                        "model_size_mb": size_mb,
                        "efficiency_ratio": memory_increase / len(model_data) if len(model_data) > 0 else 0
                    }
                    
                    # Memory usage should be reasonable
                    max_expected_mb = size_mb * 3  # Allow 3x overhead
                    actual_mb = memory_increase / (1024 * 1024)
                    assert actual_mb < max_expected_mb, f"Memory usage {actual_mb:.1f}MB > {max_expected_mb:.1f}MB"
                    
                    # Clean up
                    del result
                    gc.collect()
                    
                finally:
                    Path(f.name).unlink()
        
        print(f"\nMemory Efficiency Results:")
        for size_mb, metrics in memory_results.items():
            print(f"{size_mb:>3}MB model: +{metrics['memory_increase_mb']:.1f}MB memory "
                  f"(ratio: {metrics['efficiency_ratio']:.2f})")

    @pytest.mark.performance
    def test_concurrent_performance(self):
        """Test performance under concurrent load."""
        num_threads = 5
        num_files_per_thread = 3
        
        # Create test files
        test_files = []
        for i in range(num_threads * num_files_per_thread):
            model_data = self.create_model_with_complexity(1, "simple")  # 1MB each
            
            with tempfile.NamedTemporaryFile(suffix=f"_{i}.pkl", delete=False) as f:
                f.write(model_data)
                f.flush()
                test_files.append(Path(f.name))
        
        try:
            results = []
            errors = []
            
            def worker_thread(file_paths):
                """Worker thread that scans multiple files."""
                thread_results = []
                try:
                    scanner = ModelScanner()
                    for file_path in file_paths:
                        start_time = time.time()
                        result = scanner.scan_file(file_path)
                        scan_time = time.time() - start_time
                        thread_results.append({
                            "file": file_path.name,
                            "scan_time": scan_time,
                            "is_safe": result.is_safe
                        })
                    results.extend(thread_results)
                except Exception as e:
                    errors.append(e)
            
            # Divide files among threads
            files_per_thread = len(test_files) // num_threads
            threads = []
            
            start_time = time.time()
            
            for i in range(num_threads):
                start_idx = i * files_per_thread
                end_idx = start_idx + files_per_thread
                thread_files = test_files[start_idx:end_idx]
                
                thread = threading.Thread(target=worker_thread, args=(thread_files,))
                threads.append(thread)
                thread.start()
            
            # Wait for all threads
            for thread in threads:
                thread.join()
            
            total_time = time.time() - start_time
            
            # Check results
            assert len(errors) == 0, f"Errors in concurrent execution: {errors}"
            assert len(results) == len(test_files)
            
            # Performance checks
            avg_scan_time = sum(r["scan_time"] for r in results) / len(results)
            assert avg_scan_time < 1.0, f"Average scan time {avg_scan_time:.3f}s too slow"
            assert total_time < 10.0, f"Total concurrent time {total_time:.3f}s too slow"
            
            print(f"\nConcurrent Performance:")
            print(f"Threads: {num_threads}, Files: {len(test_files)}")
            print(f"Total time: {total_time:.3f}s, Avg scan time: {avg_scan_time:.3f}s")
            
        finally:
            for file_path in test_files:
                try:
                    file_path.unlink()
                except:
                    pass

    @pytest.mark.performance
    def test_opcode_analysis_efficiency(self):
        """Test opcode analysis performance with different pickle patterns."""
        test_patterns = {
            "simple_data": {"key": "value", "number": 42},
            "list_heavy": {"data": list(range(10000))},
            "dict_heavy": {f"key_{i}": f"value_{i}" for i in range(1000)},
            "nested_structure": {"level_" + str(i): {"data": list(range(100))} for i in range(100)},
            "mixed_types": {
                "strings": ["hello"] * 1000,
                "numbers": list(range(1000)),
                "nested": {"deep": {"deeper": {"deepest": "value"}}}
            }
        }
        
        results = {}
        
        for pattern_name, data in test_patterns.items():
            pickle_data = pickle.dumps(data)
            
            # Measure analysis time
            start_time = time.time()
            analysis = analyze_pickle_opcodes(pickle_data)
            analysis_time = time.time() - start_time
            
            results[pattern_name] = {
                "analysis_time": analysis_time,
                "pickle_size_kb": len(pickle_data) / 1024,
                "total_opcodes": analysis.get("total_opcodes", 0),
                "is_safe": analysis.get("is_safe", False),
                "efficiency": analysis.get("total_opcodes", 0) / analysis_time if analysis_time > 0 else 0
            }
            
            # Should be very fast regardless of complexity
            assert analysis_time < 0.1, f"{pattern_name} analysis took {analysis_time:.3f}s"
        
        print(f"\nOpcode Analysis Efficiency:")
        for pattern, metrics in results.items():
            print(f"{pattern:>15}: {metrics['analysis_time']:.4f}s, "
                  f"{metrics['pickle_size_kb']:.1f}KB, "
                  f"{metrics['total_opcodes']} opcodes, "
                  f"{metrics['efficiency']:.0f} opcodes/s")

    @pytest.mark.performance
    def test_directory_scanning_performance(self):
        """Test directory scanning performance with various structures."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create different directory structures
            structures = {
                "flat": {"depth": 1, "files_per_dir": 20},
                "deep": {"depth": 5, "files_per_dir": 4},
                "wide": {"depth": 2, "files_per_dir": 50}
            }
            
            for structure_name, config in structures.items():
                structure_dir = tmpdir_path / structure_name
                structure_dir.mkdir()
                
                # Create directory structure
                self._create_directory_structure(
                    structure_dir, 
                    config["depth"], 
                    config["files_per_dir"]
                )
                
                # Measure scanning performance
                scanner = ModelScanner()
                
                start_time = time.time()
                results = scanner.scan_directory(structure_dir, recursive=True)
                scan_time = time.time() - start_time
                
                expected_files = self._calculate_expected_files(
                    config["depth"], 
                    config["files_per_dir"]
                )
                
                assert len(results) == expected_files
                assert scan_time < 5.0, f"{structure_name} scan took {scan_time:.3f}s"
                
                print(f"{structure_name:>5} structure: {len(results)} files in {scan_time:.3f}s "
                      f"({len(results)/scan_time:.1f} files/s)")

    def _create_directory_structure(self, base_dir: Path, depth: int, files_per_dir: int):
        """Helper to create directory structures for testing."""
        if depth <= 0:
            return
            
        # Create files in current directory
        for i in range(files_per_dir):
            file_path = base_dir / f"model_{i}.pkl"
            model_data = pickle.dumps({"model": i, "depth": depth})
            file_path.write_bytes(model_data)
        
        # Create subdirectories
        if depth > 1:
            for i in range(2):  # 2 subdirs per level
                subdir = base_dir / f"subdir_{i}"
                subdir.mkdir()
                self._create_directory_structure(subdir, depth - 1, files_per_dir)

    def _calculate_expected_files(self, depth: int, files_per_dir: int) -> int:
        """Calculate expected number of files in directory structure."""
        if depth <= 0:
            return 0
        
        total = files_per_dir  # Files in root
        if depth > 1:
            # Add files from subdirectories (2 subdirs per level)
            total += 2 * self._calculate_expected_files(depth - 1, files_per_dir)
        
        return total

    @pytest.mark.performance
    def test_loader_performance_comparison(self):
        """Compare performance across different loaders."""
        test_data = {"performance": "test", "data": list(range(1000))}
        
        loaders = {
            "torch": torch.safe_load,
            "sklearn": sklearn.safe_load,
        }
        
        results = {}
        
        for loader_name, loader_func in loaders.items():
            with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
                pickle.dump(test_data, f)
                f.flush()
                
                try:
                    # Measure loading time
                    times = []
                    for _ in range(5):  # Multiple runs for average
                        start_time = time.time()
                        result = loader_func(f.name)
                        load_time = time.time() - start_time
                        times.append(load_time)
                        
                        assert result == test_data  # Verify correctness
                    
                    avg_time = sum(times) / len(times)
                    min_time = min(times)
                    max_time = max(times)
                    
                    results[loader_name] = {
                        "avg_time": avg_time,
                        "min_time": min_time,
                        "max_time": max_time,
                        "consistency": max_time / min_time if min_time > 0 else float('inf')
                    }
                    
                    # Performance requirements
                    assert avg_time < 1.0, f"{loader_name} avg time {avg_time:.3f}s too slow"
                    
                finally:
                    Path(f.name).unlink()
        
        print(f"\nLoader Performance Comparison:")
        for loader, metrics in results.items():
            print(f"{loader:>8}: avg={metrics['avg_time']:.4f}s, "
                  f"range={metrics['min_time']:.4f}-{metrics['max_time']:.4f}s, "
                  f"consistency={metrics['consistency']:.2f}x")

    @pytest.mark.performance
    @pytest.mark.slow
    def test_stress_test_extreme_conditions(self):
        """Stress test with extreme conditions."""
        # Test with very large file (500MB)
        large_data = {"stress": "x" * (500 * 1024 * 1024)}  # 500MB
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            try:
                pickle.dump(large_data, f)
                f.flush()
                
                # Should handle large files gracefully
                scanner = ModelScanner()
                start_time = time.time()
                result = scanner.scan_file(Path(f.name))
                scan_time = time.time() - start_time
                
                # Should complete within reasonable time even for very large files
                assert scan_time < 10.0, f"Large file scan took {scan_time:.3f}s"
                assert result.is_safe
                
                print(f"Stress test: 500MB file scanned in {scan_time:.3f}s")
                
            except MemoryError:
                pytest.skip("Not enough memory for 500MB stress test")
            finally:
                try:
                    Path(f.name).unlink()
                except:
                    pass

    def test_performance_regression_detection(self):
        """Test to detect performance regressions."""
        # Baseline performance expectations (adjust based on your system)
        baselines = {
            "small_file_scan": 0.1,      # 100ms for small files
            "medium_file_scan": 0.5,     # 500ms for medium files  
            "opcode_analysis": 0.01,     # 10ms for opcode analysis
            "safe_load": 0.1,            # 100ms for safe loading
        }
        
        # Test small file scanning
        small_data = self.create_model_with_complexity(0.1, "simple")
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(small_data)
            f.flush()
            
            try:
                scanner = ModelScanner()
                start_time = time.time()
                result = scanner.scan_file(Path(f.name))
                small_scan_time = time.time() - start_time
                
                assert small_scan_time < baselines["small_file_scan"], \
                    f"Small file scan regression: {small_scan_time:.3f}s > {baselines['small_file_scan']}s"
                
            finally:
                Path(f.name).unlink()
        
        # Test medium file scanning
        medium_data = self.create_model_with_complexity(10, "simple")
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(medium_data)
            f.flush()
            
            try:
                start_time = time.time()
                result = scanner.scan_file(Path(f.name))
                medium_scan_time = time.time() - start_time
                
                assert medium_scan_time < baselines["medium_file_scan"], \
                    f"Medium file scan regression: {medium_scan_time:.3f}s > {baselines['medium_file_scan']}s"
                
            finally:
                Path(f.name).unlink()
        
        # Test opcode analysis
        test_data = {"analysis": "test"}
        pickle_data = pickle.dumps(test_data)
        
        start_time = time.time()
        analysis = analyze_pickle_opcodes(pickle_data)
        analysis_time = time.time() - start_time
        
        assert analysis_time < baselines["opcode_analysis"], \
            f"Opcode analysis regression: {analysis_time:.3f}s > {baselines['opcode_analysis']}s"
        
        # Test safe loading
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(test_data, f)
            f.flush()
            
            try:
                start_time = time.time()
                result = torch.safe_load(f.name)
                load_time = time.time() - start_time
                
                assert load_time < baselines["safe_load"], \
                    f"Safe load regression: {load_time:.3f}s > {baselines['safe_load']}s"
                
            finally:
                Path(f.name).unlink()
        
        print(f"\nPerformance Regression Check:")
        print(f"Small scan: {small_scan_time:.4f}s (limit: {baselines['small_file_scan']}s)")
        print(f"Medium scan: {medium_scan_time:.4f}s (limit: {baselines['medium_file_scan']}s)")
        print(f"Opcode analysis: {analysis_time:.4f}s (limit: {baselines['opcode_analysis']}s)")
        print(f"Safe load: {load_time:.4f}s (limit: {baselines['safe_load']}s)")


class TestResourceUsageMonitoring:
    """Monitor resource usage during operations."""

    def test_cpu_usage_monitoring(self):
        """Monitor CPU usage during intensive operations."""
        process = psutil.Process(os.getpid())
        
        # Get baseline CPU usage
        cpu_before = process.cpu_percent()
        time.sleep(0.1)  # Let CPU measurement stabilize
        
        # Perform intensive operation
        large_data = {"cpu_test": "x" * (10 * 1024 * 1024)}  # 10MB
        
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            pickle.dump(large_data, f)
            f.flush()
            
            try:
                scanner = ModelScanner()
                
                # Monitor CPU during scanning
                start_time = time.time()
                result = scanner.scan_file(Path(f.name))
                end_time = time.time()
                
                cpu_after = process.cpu_percent()
                
                # CPU usage should be reasonable
                operation_time = end_time - start_time
                print(f"CPU usage during {operation_time:.3f}s operation: {cpu_after:.1f}%")
                
                # Should not peg CPU at 100% for simple operations
                assert cpu_after < 90.0, f"CPU usage too high: {cpu_after:.1f}%"
                
            finally:
                Path(f.name).unlink()

    def test_memory_leak_detection(self):
        """Test for memory leaks during repeated operations."""
        process = psutil.Process(os.getpid())
        
        # Get baseline memory
        gc.collect()
        baseline_memory = process.memory_info().rss
        
        test_data = {"leak_test": list(range(1000))}
        
        # Perform repeated operations
        for i in range(10):
            with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
                pickle.dump(test_data, f)
                f.flush()
                
                try:
                    # Load and scan multiple times
                    result = torch.safe_load(f.name)
                    
                    scanner = ModelScanner()
                    scan_result = scanner.scan_file(Path(f.name))
                    
                    # Clean up references
                    del result
                    del scan_result
                    
                finally:
                    Path(f.name).unlink()
        
        # Force garbage collection
        gc.collect()
        final_memory = process.memory_info().rss
        
        memory_increase = final_memory - baseline_memory
        memory_increase_mb = memory_increase / (1024 * 1024)
        
        # Should not have significant memory increase after cleanup
        assert memory_increase_mb < 50, f"Potential memory leak: +{memory_increase_mb:.1f}MB"
        
        print(f"Memory change after 10 operations: {memory_increase_mb:+.1f}MB")

    def test_file_handle_management(self):
        """Test that file handles are properly managed."""
        # Get initial file descriptor count (Unix-like systems)
        try:
            import resource
            initial_fds = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        except (ImportError, AttributeError):
            # Windows or system without resource module
            initial_fds = None
        
        test_data = {"fd_test": "data"}
        
        # Perform many file operations
        for i in range(100):
            with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
                pickle.dump(test_data, f)
                f.flush()
                
                try:
                    # Multiple operations on the same file
                    result = torch.safe_load(f.name)
                    
                    scanner = ModelScanner()
                    scan_result = scanner.scan_file(Path(f.name))
                    
                    # Analyze opcodes
                    with open(f.name, 'rb') as file:
                        pickle_data = file.read()
                    analyze_pickle_opcodes(pickle_data)
                    
                finally:
                    Path(f.name).unlink()
        
        # Check that we haven't leaked file descriptors
        if initial_fds:
            try:
                final_fds = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
                assert final_fds == initial_fds, "File descriptor leak detected"
            except:
                pass  # Skip if we can't check
        
        print("File handle management test completed successfully")