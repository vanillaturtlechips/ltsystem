from django.http import JsonResponse

def health_check(request):
    """ALB Healthcheck Ep"""
    return JsonResponse({"status": "LTS Backend is Healthy!"})

def get_traffic_data(request):
    """test API Ep"""
    mock_data = {
        "vehicle_id": "G-2321 (from Django)",
        "speed": 55,
        "status": "normal"
    }
    return JsonResponse(mock_data)