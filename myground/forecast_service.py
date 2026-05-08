# forecast_service.py
import numpy as np
from datetime import datetime, timedelta
from decimal import Decimal
from django.utils import timezone
from .models import AWSAccount, CostDataHistory, LowLevelServiceCostHistory, ResourceSummary

class CostForecastEngine:
    def __init__(self, aws_account):
        self.aws_account = aws_account
        self.historical_data = []
        self.daily_costs = []
        
    def load_historical_data(self, days=90):
        """Load historical cost data from database"""
        # Get cost data from CostDataHistory
        cost_records = CostDataHistory.objects.filter(
            aws_account=self.aws_account,
            cost_type='7_days'
        ).order_by('-updated_at')
        
        # Parse daily costs
        for record in cost_records[:30]:  # Last 30 days
            if record.data:
                for day in record.data:
                    self.daily_costs.append({
                        'date': day.get('name'),
                        'cost': day.get('cost', 0)
                    })
        
        # Get monthly data
        monthly_data = CostDataHistory.objects.filter(
            aws_account=self.aws_account,
            cost_type='monthly'
        ).first()
        
        if monthly_data and monthly_data.data:
            self.monthly_cost = float(monthly_data.data)
        
        return self.daily_costs
    
    def get_low_level_resources(self):
        """Get low-level resources for accurate forecasting"""
        from .models import LowLevelServiceResource
        
        resources = LowLevelServiceResource.objects.filter(
            account=self.aws_account,
            is_active=True
        ).select_related('service_definition')
        
        resource_costs = {}
        for resource in resources:
            service_name = resource.service_definition.name
            if service_name not in resource_costs:
                resource_costs[service_name] = 0
            resource_costs[service_name] += float(resource.estimated_monthly_cost or 0)
        
        return resource_costs
    
    def calculate_growth_rate(self):
        """Calculate historical growth rate"""
        if len(self.daily_costs) < 7:
            return 0.05  # Default 5% growth
        
        # Get last 7 days vs previous 7 days
        last_7_days = sum(d['cost'] for d in self.daily_costs[-7:]) / 7
        prev_7_days = sum(d['cost'] for d in self.daily_costs[-14:-7]) / 7
        
        if prev_7_days > 0:
            growth_rate = (last_7_days - prev_7_days) / prev_7_days
        else:
            growth_rate = 0.03
        
        return max(-0.1, min(0.2, growth_rate))  # Cap between -10% and +20%
    
    def predict_2_days(self):
        """Predict cost for next 2 days"""
        if len(self.daily_costs) < 7:
            avg_daily = self.monthly_cost / 30 if self.monthly_cost else 50
            daily_prediction = avg_daily
        else:
            # Use weighted moving average
            weights = [0.4, 0.3, 0.2, 0.1]  # More weight to recent days
            recent_costs = [d['cost'] for d in self.daily_costs[-4:]]
            daily_prediction = sum(w * c for w, c in zip(weights, recent_costs)) / sum(weights)
        
        growth_rate = self.calculate_growth_rate()
        
        predictions = []
        for i in range(1, 3):
            day_cost = daily_prediction * (1 + growth_rate * i)
            predictions.append({
                'day': i,
                'cost': round(day_cost, 2),
                'date': (timezone.now() + timedelta(days=i)).strftime('%Y-%m-%d')
            })
        
        return {
            'total': round(sum(p['cost'] for p in predictions), 2),
            'average_daily': round(sum(p['cost'] for p in predictions) / 2, 2),
            'predictions': predictions
        }
    
    def predict_1_week(self):

        """Predict cost for next 7 days"""
        if len(self.daily_costs) < 7:
            avg_daily = self.monthly_cost / 30 if self.monthly_cost else 50
            daily_prediction = avg_daily
        else:
            # Use weighted moving average with more weight on recent days
            weights = [0.35, 0.25, 0.2, 0.12, 0.08]
            recent_costs = [d['cost'] for d in self.daily_costs[-5:]]
            daily_prediction = sum(w * c for w, c in zip(weights, recent_costs)) / sum(weights)
        
        growth_rate = self.calculate_growth_rate()
        
        daily_predictions = []
        total = 0
        
        for i in range(1, 8):
            # Apply daily growth more realistically
            day_factor = 1 + (growth_rate * (i / 14))  # Slower growth accumulation
            day_cost = daily_prediction * day_factor
            daily_predictions.append({
                'day': i,
                'cost': round(day_cost, 2),
                'date': (timezone.now() + timedelta(days=i)).strftime('%Y-%m-%d')
            })
            total += day_cost
        
        return {
            'total': round(total, 2),
            'average_daily': round(total / 7, 2),
            'daily_breakdown': daily_predictions,
            'growth_rate': round(growth_rate * 100, 1)
        }
    
    def predict_1_month(self):
        
        """Predict cost for next 30 days"""
        # Get weekly average from daily data
        if len(self.daily_costs) >= 7:
            weekly_avg = sum(d['cost'] for d in self.daily_costs[-7:]) / 7
        else:
            weekly_avg = self.monthly_cost / 30 if self.monthly_cost else 50
        
        growth_rate = self.calculate_growth_rate()
        
        monthly_total = 0
        weekly_predictions = []
        
        for week in range(1, 5):
            # Apply growth per week (4 weeks in a month)
            week_factor = 1 + (growth_rate * (week / 4))
            week_cost = weekly_avg * 7 * week_factor
            cumulative = monthly_total + week_cost
            weekly_predictions.append({
                'week': week,
                'cost': round(week_cost, 2),
                'cumulative': round(cumulative, 2)
            })
            monthly_total += week_cost
        
        # Calculate vs current month
        vs_current = 0
        if self.monthly_cost and self.monthly_cost > 0:
            vs_current = ((monthly_total - self.monthly_cost) / self.monthly_cost) * 100
        
        return {
            'total': round(monthly_total, 2),
            'average_daily': round(monthly_total / 30, 2),
            'weekly_breakdown': weekly_predictions,
            'vs_current_month': round(vs_current, 1)
        }
    
    def predict_2_months(self):
        """Predict cost for next 60 days"""
        monthly_prediction = self.predict_1_month()['total']
        growth_rate = self.calculate_growth_rate()
        
        month1 = monthly_prediction
        month2 = monthly_prediction * (1 + growth_rate)
        
        return {
            'month1': round(month1, 2),
            'month2': round(month2, 2),
            'total': round(month1 + month2, 2),
            'average_monthly': round((month1 + month2) / 2, 2),
            'growth_rate': round(growth_rate * 100, 1)
        }
    
    def predict_3_months(self):
        """Predict cost for next 90 days"""
        monthly_prediction = self.predict_1_month()['total']
        growth_rate = self.calculate_growth_rate()
        
        months = []
        total = 0
        
        for i in range(1, 4):
            month_cost = monthly_prediction * (1 + growth_rate * (i - 1))
            months.append({
                'month': i,
                'cost': round(month_cost, 2),
                'cumulative': round(total + month_cost, 2)
            })
            total += month_cost
        
        return {
            'month1': round(months[0]['cost'], 2),
            'month2': round(months[1]['cost'], 2),
            'month3': round(months[2]['cost'], 2),
            'total': round(total, 2),
            'average_monthly': round(total / 3, 2),
            'months_breakdown': months
        }
    
    def get_top_growing_services(self, limit=5):
        """Identify services with fastest cost growth"""
        from .models import LowLevelServiceCostHistory
        from datetime import timedelta
        
        thirty_days_ago = timezone.now().date() - timedelta(days=30)
        fifteen_days_ago = timezone.now().date() - timedelta(days=15)
        
        # Get cost history for last 30 days
        cost_history = LowLevelServiceCostHistory.objects.filter(
            account=self.aws_account,
            date__gte=thirty_days_ago
        ).select_related('service_definition')
        
        service_costs = {}
        
        for record in cost_history:
            service_name = record.service_definition.name
            if service_name not in service_costs:
                service_costs[service_name] = {
                    'first_half': 0,
                    'second_half': 0,
                    'count_first': 0,
                    'count_second': 0
                }
            
            if record.date < fifteen_days_ago:
                service_costs[service_name]['first_half'] += float(record.monthly_cost or 0)
                service_costs[service_name]['count_first'] += 1
            else:
                service_costs[service_name]['second_half'] += float(record.monthly_cost or 0)
                service_costs[service_name]['count_second'] += 1
        
        # Calculate growth rates
        growing_services = []
        for service, data in service_costs.items():
            avg_first = data['first_half'] / max(data['count_first'], 1)
            avg_second = data['second_half'] / max(data['count_second'], 1)
            
            if avg_first > 0:
                growth = ((avg_second - avg_first) / avg_first) * 100
            else:
                growth = 0
            
            if growth > 5:  # Only show services with >5% growth
                growing_services.append({
                    'service': service,
                    'growth_rate': round(growth, 1),
                    'current_cost': round(avg_second, 2),
                    'previous_cost': round(avg_first, 2),
                    'cost_increase': round(avg_second - avg_first, 2)
                })
        
        return sorted(growing_services, key=lambda x: x['growth_rate'], reverse=True)[:limit]
    
    def get_service_forecast(self, service_name):
        """Get individual service forecast"""
        from .models import LowLevelServiceCostHistory
        
        # Get last 3 months of data for this service
        ninety_days_ago = timezone.now().date() - timedelta(days=90)
        cost_records = LowLevelServiceCostHistory.objects.filter(
            account=self.aws_account,
            service_definition__name=service_name,
            date__gte=ninety_days_ago
        ).order_by('date')
        
        if not cost_records:
            return None
        
        # Calculate trend
        costs = [float(record.monthly_cost) for record in cost_records]
        if len(costs) >= 2:
            trend = (costs[-1] - costs[0]) / len(costs)
        else:
            trend = costs[0] * 0.05
        
        # Predict next 3 months
        predictions = []
        current_cost = costs[-1] if costs else 0
        
        for i in range(1, 4):
            predicted_cost = current_cost + (trend * i * 30)
            predictions.append({
                'month': i,
                'cost': round(max(0, predicted_cost), 2),
                'date': (timezone.now() + timedelta(days=30*i)).strftime('%Y-%m')
            })
        
        return {
            'service': service_name,
            'current_cost': round(current_cost, 2),
            'trend': 'increasing' if trend > 0 else 'decreasing' if trend < 0 else 'stable',
            'trend_rate': round(abs(trend), 2),
            'predictions': predictions,
            'next_month_cost': round(max(0, current_cost + trend * 30), 2),
            'quarterly_cost': round(sum(p['cost'] for p in predictions), 2)
        }
    
    def get_all_service_forecasts(self):
        """Get forecasts for all active services"""
        from .models import LowLevelServiceResource
        
        # Get unique services from active resources
        services = LowLevelServiceResource.objects.filter(
            account=self.aws_account,
            is_active=True
        ).values_list('service_definition__name', flat=True).distinct()
        
        forecasts = []
        for service_name in services:
            forecast = self.get_service_forecast(service_name)
            if forecast:
                forecasts.append(forecast)
        
        return sorted(forecasts, key=lambda x: x['current_cost'], reverse=True)