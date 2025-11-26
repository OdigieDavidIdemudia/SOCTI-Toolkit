import main


def test_add_separator_basic():
    assert main.add_separator("david odigie mick ide victor") == "david,odigie,mick,ide,victor"


def test_multiple_spaces_and_commas():
    assert main.add_separator("  david,   odigie   mick ") == "david,odigie,mick"


def test_custom_separator():
    assert main.add_separator("a b c", sep='|') == "a|b|c"


def test_empty_and_none():
    assert main.add_separator("") == ""
    assert main.add_separator(None) == ""


def test_special_characters():
    """Test handling of special characters in input."""
    assert main.add_separator("hello@world test#123") == "hello@world,test#123"
    assert main.add_separator("user@email.com another@email.com") == "user@email.com,another@email.com"


def test_numbers_and_mixed():
    """Test handling of numbers and mixed content."""
    assert main.add_separator("123 456 789") == "123,456,789"
    assert main.add_separator("item1 item2 item3", sep=';') == "item1;item2;item3"


def test_multiline_input():
    """Test handling of multiline input."""
    multiline = """line1
    line2
    line3"""
    assert main.add_separator(multiline) == "line1,line2,line3"
