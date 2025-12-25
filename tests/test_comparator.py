from comparator import NormalizationEngine, ComparisonEngine

def test_normalization():
    norm = NormalizationEngine()
    
    # Test 1: Comma and newline replacement
    raw = "a,b\nc" 
    # normalize: replace \n with , -> "a,b,c" -> split -> ["a", "b", "c"]
    assert norm.normalize(raw) == ["a", "b", "c"]
    
    # Test 2: Whitespace trimming and empty removal
    raw = " a ,  b  ,, \n c "
    # replace \n->,: " a ,  b  ,, , c "
    # split: [" a ", "  b  ", "", "", " c "]
    # trim: ["a", "b", "", "", "c"]
    # remove empty: ["a", "b", "c"]
    # deduplicate: ["a", "b", "c"] (already unique)
    assert norm.normalize(raw) == ["a", "b", "c"]
    
    # Test 3: Deduplication
    raw = "a,a,b,b,c"
    assert norm.normalize(raw) == ["a", "b", "c"]
    
    # Test 4: Empty input
    assert norm.normalize("") == []
    assert norm.normalize(None) == []

def test_comparison():
    comp = ComparisonEngine()
    
    # Setup
    list_a = ["apple", "banana", "cherry"]
    list_b = ["banana", "date", "fig"]
    
    result = comp.compare(list_a, list_b)
    
    # Common: banana
    assert result['common'] == ["banana"]
    
    # Unique A: apple, cherry
    # Expect sorted output
    assert result['unique_to_a'] == ["apple", "cherry"]
    
    # Unique B: date, fig
    assert result['unique_to_b'] == ["date", "fig"]

def test_comparison_identical():
    comp = ComparisonEngine()
    list_a = ["x", "y"]
    list_b = ["x", "y"]
    result = comp.compare(list_a, list_b)
    assert result['common'] == ["x", "y"]
    assert result['unique_to_a'] == []
    assert result['unique_to_b'] == []

def test_comparison_disjoint():
    comp = ComparisonEngine()
    list_a = ["a"]
    list_b = ["b"]
    result = comp.compare(list_a, list_b)
    assert result['common'] == []
    assert result['unique_to_a'] == ["a"]
    assert result['unique_to_b'] == ["b"]
