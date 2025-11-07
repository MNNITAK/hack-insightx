/**
 * API Route: Architectures Storage
 * Handles CRUD operations for architecture storage
 */

import { NextRequest, NextResponse } from 'next/server';
import { connectToDatabase } from '../../../lib/dbConnection';

// Import MongoDB models
const ArchitectureStorage = require('../../../lib/models/ArchitectureStorage');

/**
 * GET /api/architectures - Get user's architectures
 * Query params: user_id, limit, offset
 */
export async function GET(request: NextRequest) {
  try {
    await connectToDatabase();
    
    const { searchParams } = new URL(request.url);
    const user_id = searchParams.get('user_id') || 'sample_user_123';
    const limit = parseInt(searchParams.get('limit') || '20');
    const offset = parseInt(searchParams.get('offset') || '0');
    
    const architectures = await ArchitectureStorage.findByUserId(user_id)
      .limit(limit)
      .skip(offset)
      .sort({ created_at: -1 });
    
    return NextResponse.json({
      success: true,
      data: architectures,
      count: architectures.length
    });
    
  } catch (error) {
    console.error('Error fetching architectures:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to fetch architectures' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/architectures - Save new architecture
 */
export async function POST(request: NextRequest) {
  try {
    await connectToDatabase();
    
    const body = await request.json();
    const {
      user_id = 'sample_user_123',
      architecture_data,
      metadata,
      trigger_info
    } = body;
    
    // Validate required fields
    if (!architecture_data) {
      return NextResponse.json(
        { success: false, error: 'Architecture data is required' },
        { status: 400 }
      );
    }
    
    // Create new architecture storage document
    const architectureStorage = new ArchitectureStorage({
      user_id,
      architecture_id: `arch_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      current_metadata: {
        company_name: architecture_data?.metadata?.company_name || 'Untitled Architecture',
        architecture_type: architecture_data?.metadata?.architecture_type || 'custom',
        security_level: architecture_data?.metadata?.security_level || 'medium',
        description: architecture_data?.metadata?.description || ''
      },
      versions: [{
        version_name: 'v1.0',
        version_number: 1,
        description: 'Initial version',
        is_current: true,
        metadata: {
          company_name: architecture_data?.metadata?.company_name || 'Untitled Architecture',
          architecture_type: architecture_data?.metadata?.architecture_type || 'custom',
          created_at: new Date(architecture_data?.metadata?.created_at || Date.now()),
          updated_at: new Date(),
          security_level: architecture_data?.metadata?.security_level || 'medium',
          description: architecture_data?.metadata?.description || ''
        },
        nodes: architecture_data?.nodes || [],
        connections: architecture_data?.connections || [],
        network_zones: architecture_data?.network_zones || [],
        trigger_type: trigger_info?.trigger_type || 'manual_save',
        trigger_id: trigger_info?.trigger_id
      }]
    });
    
    const savedArchitecture = await architectureStorage.save();
    
    return NextResponse.json({
      success: true,
      data: savedArchitecture,
      message: 'Architecture saved successfully'
    });
    
  } catch (error) {
    console.error('Error saving architecture:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to save architecture' },
      { status: 500 }
    );
  }
}

/**
 * PUT /api/architectures - Update existing architecture
 */
export async function PUT(request: NextRequest) {
  try {
    await connectToDatabase();
    
    const body = await request.json();
    const {
      architecture_id,
      user_id = 'sample_user_123',
      architecture_data,
      metadata,
      trigger_info
    } = body;
    
    if (!architecture_id) {
      return NextResponse.json(
        { success: false, error: 'Architecture ID is required' },
        { status: 400 }
      );
    }
    
    // Find the architecture
    const architectureStorage = await ArchitectureStorage.findOne({
      architecture_id,
      user_id
    });
    
    if (!architectureStorage) {
      return NextResponse.json(
        { success: false, error: 'Architecture not found' },
        { status: 404 }
      );
    }
    
    // Add new version
    const newVersion = await architectureStorage.addNewVersion(
      architecture_data,
      {
        name: metadata?.name,
        description: metadata?.description,
        tags: metadata?.tags,
        ...metadata
      },
      {
        trigger_type: trigger_info?.trigger_type || 'manual',
        trigger_id: trigger_info?.trigger_id,
        notes: trigger_info?.notes || ''
      }
    );
    
    return NextResponse.json({
      success: true,
      data: newVersion,
      message: 'Architecture updated successfully'
    });
    
  } catch (error) {
    console.error('Error updating architecture:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to update architecture' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/architectures - Delete architecture
 */
export async function DELETE(request: NextRequest) {
  try {
    await connectToDatabase();
    
    const { searchParams } = new URL(request.url);
    const architecture_id = searchParams.get('architecture_id');
    const user_id = searchParams.get('user_id') || 'sample_user_123';
    
    if (!architecture_id) {
      return NextResponse.json(
        { success: false, error: 'Architecture ID is required' },
        { status: 400 }
      );
    }
    
    const result = await ArchitectureStorage.deleteOne({
      architecture_id,
      user_id
    });
    
    if (result.deletedCount === 0) {
      return NextResponse.json(
        { success: false, error: 'Architecture not found' },
        { status: 404 }
      );
    }
    
    return NextResponse.json({
      success: true,
      message: 'Architecture deleted successfully'
    });
    
  } catch (error) {
    console.error('Error deleting architecture:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to delete architecture' },
      { status: 500 }
    );
  }
}