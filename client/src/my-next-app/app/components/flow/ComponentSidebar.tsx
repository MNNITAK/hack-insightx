/**
 * Component Sidebar
 * Displays categorized components that can be dragged onto the canvas
 * Supports search and filtering functionality
 */

'use client';

import React, { useState, useMemo } from 'react';
import { ComponentCategory, ComponentConfiguration } from '../../types';
import { useComponentRegistry } from '../../utils/componentRegistry';
import { Button } from '../ui/button';
import { 
  FiSearch, 
  FiChevronDown, 
  FiChevronRight,
  FiLayers,
  FiMaximize2,
  FiMinimize2
} from 'react-icons/fi';
import { 
  HiOutlineCloud,
  HiOutlineShieldCheck,
  HiOutlineGlobeAlt,
  HiOutlineCpuChip,
  HiOutlineServerStack,
  HiOutlineDevicePhoneMobile,
  HiOutlineCog6Tooth,
  HiOutlineCubeTransparent
} from 'react-icons/hi2';

interface ComponentSidebarProps {
  className?: string;
}

interface DraggableComponentProps {
  component: ComponentConfiguration;
  onDragStart: (component: ComponentConfiguration) => void;
}

/**
 * Individual draggable component item
 */
const DraggableComponent: React.FC<DraggableComponentProps> = ({ 
  component, 
  onDragStart 
}) => {
  const handleDragStart = (e: React.DragEvent) => {
    // Set drag data for drop handling
    e.dataTransfer.setData('application/reactflow', JSON.stringify({
      type: 'component',
      componentType: component.component_type,
      componentConfig: component
    }));
    
    // Call parent handler
    onDragStart(component);
  };

  return (
    <div
      draggable
      onDragStart={handleDragStart}
      className="flex items-center gap-3 p-3.5 rounded-lg border border-slate-700/50 hover:border-cyan-500/60 bg-slate-800/40 hover:bg-slate-700/60 cursor-grab active:cursor-grabbing transition-all duration-300 group backdrop-blur-sm hover:shadow-lg hover:shadow-cyan-500/10"
    >
      <div className="text-2xl flex-shrink-0 text-cyan-400">
        {component.icon}
      </div>
      <div className="flex-1 min-w-0">
        <div className="font-semibold text-sm text-slate-100 truncate tracking-wide">
          {component.component_type.replace(/_/g, ' ').toUpperCase()}
        </div>
        <div className="text-xs text-slate-400 truncate mt-0.5">
          {component.description}
        </div>
      </div>
      <div className="opacity-0 group-hover:opacity-100 transition-opacity">
        <div className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse shadow-lg shadow-cyan-400/50"></div>
      </div>
    </div>
  );
};

/**
 * Category section with collapsible components
 */
interface CategorySectionProps {
  category: ComponentCategory;
  isExpanded: boolean;
  onToggle: () => void;
  onComponentDragStart: (component: ComponentConfiguration) => void;
}

const CategorySection: React.FC<CategorySectionProps> = ({
  category,
  isExpanded,
  onToggle,
  onComponentDragStart
}) => {
  // Icon mapping for categories
  const getCategoryIcon = (categoryId: string) => {
    const iconMap: Record<string, React.ReactElement> = {
      cloud: <HiOutlineCloud className="w-5 h-5" />,
      security: <HiOutlineShieldCheck className="w-5 h-5" />,
      network: <HiOutlineGlobeAlt className="w-5 h-5" />,
      compute: <HiOutlineCpuChip className="w-5 h-5" />,
      data: <HiOutlineServerStack className="w-5 h-5" />,
      endpoints: <HiOutlineDevicePhoneMobile className="w-5 h-5" />,
      specialized: <HiOutlineCog6Tooth className="w-5 h-5" />,
      infrastructure: <HiOutlineCubeTransparent className="w-5 h-5" />
    };
    return iconMap[categoryId] || <FiLayers className="w-5 h-5" />;
  };

  return (
    <div className="border border-slate-700/30 rounded-xl overflow-hidden bg-slate-800/30 backdrop-blur-sm hover:border-cyan-500/30 transition-all duration-300">
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 p-4 bg-slate-800/50 hover:bg-slate-700/50 transition-all duration-200 group"
      >
        <span className="text-cyan-400 group-hover:text-cyan-300 transition-colors">{getCategoryIcon(category.id)}</span>
        <span className="flex-1 text-left font-bold text-slate-100 tracking-wide uppercase text-sm">
          {category.name}
        </span>
        <span className="text-xs bg-cyan-500/20 text-cyan-300 px-3 py-1 rounded-full font-semibold border border-cyan-500/30">
          {category.components.length}
        </span>
        {isExpanded ? (
          <FiChevronDown className="text-slate-400 w-4 h-4" />
        ) : (
          <FiChevronRight className="text-slate-400 w-4 h-4" />
        )}
      </button>
      
      {isExpanded && (
        <div className="p-3 space-y-2 bg-slate-900/40">
          {category.components.map((component) => (
            <DraggableComponent
              key={component.component_type}
              component={component}
              onDragStart={onComponentDragStart}
            />
          ))}
        </div>
      )}
    </div>
  );
};



/**
 * Main sidebar component
 */
export const ComponentSidebar: React.FC<ComponentSidebarProps> = ({ 
  className 
}) => {
  const { getComponentsByCategory, searchComponents } = useComponentRegistry();
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());
  const [draggedComponent, setDraggedComponent] = useState<ComponentConfiguration | null>(null);

  // Get categories and filter based on search
  const categories = useMemo(() => {
    const allCategories = getComponentsByCategory();
    
    if (!searchQuery.trim()) {
      return Object.entries(allCategories).map(([categoryName, components]) => ({
        id: categoryName,
        name: categoryName.charAt(0).toUpperCase() + categoryName.slice(1),
        icon: '', // Icon will be rendered by getCategoryIcon function
        components: components
      }));
    }
    
    // Search across all components
    const searchResults = searchComponents(searchQuery);
    const searchCategories: Record<string, ComponentConfiguration[]> = {};
    
    searchResults.forEach((component: ComponentConfiguration) => {
      if (!searchCategories[component.category]) {
        searchCategories[component.category] = [];
      }
      searchCategories[component.category].push(component);
    });

    return Object.entries(searchCategories)
      .map(([categoryName, components]) => ({
        id: categoryName,
        name: categoryName.charAt(0).toUpperCase() + categoryName.slice(1),
        icon: '', // Icon will be rendered by getCategoryIcon function
        components: components
      }))
      .filter((category: any) => category.components.length > 0);
  }, [getComponentsByCategory, searchComponents, searchQuery]);

  // Toggle category expansion
  const toggleCategory = (categoryId: string) => {
    const newExpanded = new Set(expandedCategories);
    if (newExpanded.has(categoryId)) {
      newExpanded.delete(categoryId);
    } else {
      newExpanded.add(categoryId);
    }
    setExpandedCategories(newExpanded);
  };

  // Expand all categories
  const expandAll = () => {
    setExpandedCategories(new Set(categories.map(cat => cat.id)));
  };

  // Collapse all categories
  const collapseAll = () => {
    setExpandedCategories(new Set());
  };

  // Handle component drag start
  const handleComponentDragStart = (component: ComponentConfiguration) => {
    setDraggedComponent(component);
  };

  // Handle drag end
  const handleDragEnd = () => {
    setDraggedComponent(null);
  };

  return (
    <div 
      className={`w-80 bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950 border-r border-slate-800 flex flex-col h-full shadow-2xl ${className}`}
      onDragEnd={handleDragEnd}
    >
      {/* Header */}
      <div className="p-5 border-b border-slate-800/50 bg-slate-900/80 backdrop-blur-sm">
        <div className="flex items-center gap-3 mb-4">
          <FiLayers className="w-6 h-6 text-cyan-400" />
          <h2 className="text-xl font-bold text-slate-100 tracking-tight">
            Components
          </h2>
        </div>
        
        {/* Search */}
        <div className="relative mb-4">
          <FiSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-500 w-4 h-4" />
          <input
            type="text"
            placeholder="Search components..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 bg-slate-800/70 border border-slate-700/50 rounded-lg text-slate-200 placeholder-slate-500 focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500/50 transition-all font-medium"
          />
        </div>
        
        {/* Controls */}
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={expandAll}
            className="flex-1 bg-slate-800/50 border-slate-700/50 text-slate-300 hover:bg-cyan-500/10 hover:text-cyan-400 hover:border-cyan-500/50 font-semibold"
          >
            <FiMaximize2 className="w-3.5 h-3.5 mr-1.5" />
            Expand
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={collapseAll}
            className="flex-1 bg-slate-800/50 border-slate-700/50 text-slate-300 hover:bg-cyan-500/10 hover:text-cyan-400 hover:border-cyan-500/50 font-semibold"
          >
            <FiMinimize2 className="w-3.5 h-3.5 mr-1.5" />
            Collapse
          </Button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 custom-scrollbar">
        {categories.length === 0 ? (
          <div className="text-center py-12 text-slate-400">
            <FiSearch className="w-12 h-12 mx-auto mb-3 text-slate-600" />
            <p className="text-slate-300 font-semibold mb-1">No components found</p>
            {searchQuery && (
              <p className="text-sm text-slate-500">Try a different search term</p>
            )}
          </div>
        ) : (
          <div className="space-y-3">
            {categories.map((category) => (
              <CategorySection
                key={category.id}
                category={category}
                isExpanded={expandedCategories.has(category.id)}
                onToggle={() => toggleCategory(category.id)}
                onComponentDragStart={handleComponentDragStart}
              />
            ))}
          </div>
        )}
      </div>

      {/* Footer with drag hint */}
      <div className="p-4 border-t border-slate-800/50 bg-slate-900/80 backdrop-blur-sm">
        <div className="text-xs text-slate-400 text-center font-medium">
          {draggedComponent ? (
            <div className="flex items-center justify-center gap-2 text-cyan-400">
              <div className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse shadow-lg shadow-cyan-400/50"></div>
              <span className="font-semibold">Dragging {draggedComponent.component_type}</span>
            </div>
          ) : (
            <span className="text-slate-500">Drag components to canvas to build architecture</span>
          )}
        </div>
      </div>
    </div>
  );
};