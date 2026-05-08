# low_level_db_service.py
from .models import (
      AWSAccount, LowLevelServiceSnapshot, LowLevelServiceResource,
    LowLevelServiceDefinition, LowLevelServiceCategory, LowLevelServiceCostHistory
)
from django.utils import timezone
from decimal import Decimal
import time

class LowLevelServiceDB:
    """Database-first service for low-level AWS resources"""
    
    @staticmethod
    def get_services(account_id, force_refresh=False):
        """Get low-level services from database, refresh if needed"""
        try:
            account =  AWSAccount.objects.get(id=account_id)
            
            # Check if we have a recent snapshot (less than 24 hours old)
            if not force_refresh:
                latest_snapshot = LowLevelServiceSnapshot.objects.filter(
                    account=account
                ).order_by('-created_at').first()
                
                if latest_snapshot:
                    # Check if snapshot is less than 24 hours old
                    age_hours = (timezone.now() - latest_snapshot.created_at).total_seconds() / 3600
                    if age_hours < 24:
                        print(f"📦 Using database snapshot from {age_hours:.1f} hours ago")
                        return latest_snapshot.snapshot_data
            
            # Need fresh data
            print(f"🔄 Fetching fresh low-level services for {account.account_id}")
            start_time = time.time()
            
            from .low_level_tracker import discover_low_level_services
            services_data = discover_low_level_services(account_id, use_cache=False)
            
            if services_data and 'error' not in services_data:
                # Save to database
                LowLevelServiceDB.save_snapshot(account, services_data)
                
                # Add timing info
                services_data['scan_duration'] = round(time.time() - start_time, 2)
                print(f"✅ Saved snapshot in {services_data['scan_duration']} seconds")
                
                return services_data
            
            return services_data
            
        except Exception as e:
            print(f"❌ Error getting low-level services: {e}")
            return {'error': str(e)}
    
    @staticmethod
    def save_snapshot(account, services_data):
        """Save low-level services snapshot to database"""
        from django.db import transaction
        
        with transaction.atomic():
            # Create snapshot
            snapshot = LowLevelServiceSnapshot.objects.create(
                account=account,
                total_services=services_data['summary']['total_services'],
                estimated_monthly_cost=Decimal(str(services_data['summary']['estimated_monthly_cost'])),
                unique_service_types=services_data['summary']['unique_service_types'],
                unique_services_discovered=services_data['summary'].get('unique_services_discovered', 0),
                regions_scanned=services_data['summary'].get('regions_scanned', []),
                snapshot_data=services_data,
                scan_duration_seconds=services_data.get('scan_duration')
            )
            
            # Mark old resources as inactive
            LowLevelServiceResource.objects.filter(
                account=account, 
                is_active=True
            ).update(is_active=False)
            
            # Save all resources
            for service_id, category_data in services_data['services_by_category'].items():
                # Get or create category
                category, _ = LowLevelServiceCategory.objects.get_or_create(
                    key=category_data['category'].lower().replace(' ', '_'),
                    defaults={'name': category_data['category']}
                )
                
                # Get or create service definition
                service_info = category_data['service_info']
                service_def, _ = LowLevelServiceDefinition.objects.get_or_create(
                    service_id=service_id,
                    defaults={
                        'name': service_info['name'],
                        'description': service_info['description'],
                        'category': category,
                        'unit': service_info.get('unit', ''),
                        'price_per_hour': Decimal(str(service_info.get('price_per_hour', 0))) if service_info.get('price_per_hour') else None,
                        'price_per_gb': Decimal(str(service_info.get('price_per_gb', 0))) if service_info.get('price_per_gb') else None,
                        'price_per_gb_month': Decimal(str(service_info.get('price_per_gb_month', 0))) if service_info.get('price_per_gb_month') else None,
                        'price_per_million': Decimal(str(service_info.get('price_per_million', 0))) if service_info.get('price_per_million') else None,
                        'price_per_month': Decimal(str(service_info.get('price_per_month', 0))) if service_info.get('price_per_month') else None,
                    }
                )
                
                # Save each resource
                for resource in category_data['resources']:
                    LowLevelServiceResource.objects.update_or_create(
                        account=account,
                        service_definition=service_def,
                        resource_id=resource['resource_id'],
                        region=resource['region'],
                        defaults={
                            'resource_name': resource.get('resource_name', ''),
                            'count': resource.get('count', 1),
                            'estimated_monthly_cost': Decimal(str(resource.get('estimated_monthly_cost', 0))),
                            'details': resource.get('details', {}),
                            'discovered_at': snapshot.created_at,
                            'is_active': True
                        }
                    )
                
                # Save cost history
                today = timezone.now().date()
                LowLevelServiceCostHistory.objects.update_or_create(
                    account=account,
                    service_definition=service_def,
                    date=today,
                    defaults={
                        'monthly_cost': Decimal(str(category_data['total_monthly_cost'])),
                        'resource_count': category_data['total_count'],
                        'region_breakdown': {
                            r['region']: float(r['estimated_monthly_cost'])
                            for r in category_data['resources']
                        }
                    }
                )
            
            return snapshot
    
    @staticmethod
    def get_service_history(account_id, service_id=None, days=30):
        """Get historical cost data for services"""
        account =   AWSAccount.objects.get(id=account_id)
        
        history = LowLevelServiceCostHistory.objects.filter(
            account=account,
            date__gte=timezone.now().date() - timezone.timedelta(days=days)
        )
        
        if service_id:
            service_def = LowLevelServiceDefinition.objects.get(service_id=service_id)
            history = history.filter(service_definition=service_def)
        
        return history.order_by('date')
    
    @staticmethod
    def get_resources_by_category(account_id, category):
        """Get resources filtered by category"""
        account =  AWSAccount.objects.get(id=account_id)
        
        return LowLevelServiceResource.objects.filter(
            account=account,
            service_definition__category__name__iexact=category,
            is_active=True
        ).select_related('service_definition')
    
    @staticmethod
    def get_cost_summary(account_id):
        """Get cost summary from latest snapshot"""
        account =  AWSAccount.objects.get(id=account_id)
        
        latest = LowLevelServiceSnapshot.objects.filter(
            account=account
        ).order_by('-created_at').first()
        
        if not latest:
            return None
        
        # Get cost by category from snapshot data
        cost_by_category = {}
        for service_id, category_data in latest.snapshot_data.get('services_by_category', {}).items():
            category = category_data.get('category', 'Other')
            cost = category_data.get('total_monthly_cost', 0)
            
            if category not in cost_by_category:
                cost_by_category[category] = 0
            cost_by_category[category] += cost
        
        return {
            'total_monthly_cost': float(latest.estimated_monthly_cost),
            'total_resources': latest.total_services,
            'unique_service_types': latest.unique_service_types,
            'unique_services': latest.unique_services_discovered,
            'regions_scanned': latest.regions_scanned,
            'last_updated': latest.created_at,
            'scan_duration': latest.scan_duration_seconds,
            'cost_by_category': cost_by_category,
            'cached': True,
            'source': 'database'
        }